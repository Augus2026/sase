use crate::common::{ClientConfig, PacketType, VpnPacket, TUN_MTU, tun_io_task, print_packet_info};
use crate::transport::Transport;
use crate::tcp_transport::TcpTransport;
use crate::udp_transport::UdpTransport;
use anyhow::Result;
use log::{error, info, warn};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{interval, sleep};
use tun2::{create_as_async, Configuration};

async fn handshake_async(transport: &dyn Transport, server_addr: std::net::SocketAddr) -> Result<u32> {
    info!("Connecting to server at {}", server_addr);

    let handshake_packet = VpnPacket::new(PacketType::Handshake, 0, 0, 0);
    let handshake_buf = handshake_packet.to_bytes();

    let mut retry_delay = Duration::from_secs(1);
    let max_retry_delay = Duration::from_secs(300);
    let mut attempt = 0u32;

    loop {
        attempt += 1;
        info!("Handshake attempt {} to {}", attempt, server_addr);

        transport.send_to(&handshake_buf, server_addr).await?;
        info!("Handshake sent to {}", server_addr);

        let timeout = sleep(Duration::from_secs(5));
        tokio::pin!(timeout);

        let mut recv_buf = [0u8; VpnPacket::HEADER_SIZE];

        tokio::select! {
            result = transport.recv_from(&mut recv_buf) => {
                match result {
                    Ok((n, addr)) => {
                        if addr == server_addr {
                            match VpnPacket::from_bytes(&recv_buf[..n]) {
                                Ok(header) if header.packet_type == PacketType::Handshake => {
                                    info!("Connected! Client ID: {}", header.client_id);
                                    return Ok(header.client_id);
                                }
                                _ => {
                                    info!("Unexpected packet during handshake");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        info!("Error during handshake attempt {}: {}", attempt, e);
                    }
                }
            }
            _ = &mut timeout => {
                info!("Handshake attempt {} timed out", attempt);
            }
        }

        warn!("Connection failed, retrying in {}s...", retry_delay.as_secs());
        sleep(retry_delay).await;
        retry_delay = std::cmp::min(retry_delay * 2, max_retry_delay);
    }
}

async fn transport_io_task(
    transport: Arc<dyn Transport>,
    server_addr: std::net::SocketAddr,
    client_id: u32,
    mut tun_rx: mpsc::Receiver<Vec<u8>>,
    transport_tx: mpsc::Sender<Vec<u8>>,
) {
    let mut transport_buf = vec![0u8; VpnPacket::HEADER_SIZE + TUN_MTU];
    let mut keepalive_interval = interval(Duration::from_secs(10));
    let mut sequence = 0u32;
    info!("Transport I/O task started for client {}", client_id);

    loop {
        tokio::select! {
            result = transport.recv_from(&mut transport_buf) => {
                match result {
                    Ok((n, src_addr)) => {
                        if src_addr != server_addr {
                            info!("Transport: Received packet from unexpected address: {}", src_addr);
                            continue;
                        }

                        if n < VpnPacket::HEADER_SIZE {
                            info!("Transport: Received short packet");
                            continue;
                        }

                        match VpnPacket::from_bytes(&transport_buf[..n]) {
                            Ok(header) => {
                                if header.client_id != client_id {
                                    continue;
                                }

                                match header.packet_type {
                                    PacketType::Data => {
                                        let payload_start = VpnPacket::HEADER_SIZE;
                                        let payload_end = payload_start + header.length as usize;

                                        if payload_end <= n {
                                            let payload = transport_buf[payload_start..payload_end].to_vec();

                                            print_packet_info("[transport recv]", &payload);
                                            if let Err(e) = transport_tx.send(payload).await {
                                                error!("Transport: Failed to send to TUN: {}", e);
                                                break;
                                            }
                                        }
                                    }
                                    PacketType::KeepAlive => {
                                        info!("Keepalive received from server");
                                    }
                                    PacketType::Disconnect => {
                                        warn!("Server disconnected");
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                            Err(e) => {
                                info!("Transport: Failed to parse packet: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Transport: Error receiving: {}", e);
                        break;
                    }
                }
            }

            result = tun_rx.recv() => {
                match result {
                    Some(data) => {
                        let packet = VpnPacket::new(PacketType::Data, client_id, sequence, data.len() as u16);
                        sequence = sequence.wrapping_add(1);

                        let mut send_buf = vec![0u8; VpnPacket::HEADER_SIZE + data.len()];
                        send_buf[..VpnPacket::HEADER_SIZE].copy_from_slice(&packet.to_bytes());
                        send_buf[VpnPacket::HEADER_SIZE..].copy_from_slice(&data);

                        print_packet_info("[transport send]", &data);
                        if let Err(e) = transport.send_to(&send_buf, server_addr).await {
                            warn!("Transport: Failed to send to server: {}", e);
                        }
                    }
                    None => {
                        error!("Transport: Channel disconnected");
                        break;
                    }
                }
            }

            _ = keepalive_interval.tick() => {
                let packet = VpnPacket::new(PacketType::KeepAlive, client_id, sequence, 0);
                sequence = sequence.wrapping_add(1);
                let buf = packet.to_bytes();

                if let Err(e) = transport.send_to(&buf, server_addr).await {
                    warn!("Keepalive: Failed to send: {}", e);
                }
            }
        }
    }
}

pub async fn run_client(config: ClientConfig, transport_type: String) -> Result<()> {
    info!("Creating TUN device: {}", config.tun_name);

    let mut tun_config = Configuration::default();
    tun_config
        .tun_name(&config.tun_name)
        .layer(tun2::Layer::L3)
        .mtu(config.mtu as u16)
        .address(config.tun_addr)
        .netmask(config.tun_netmask)
        .up();

    let tun = create_as_async(&tun_config)?;
    info!("TUN device created: {} -> {}", config.tun_name, config.tun_addr);

    let transport: Arc<dyn Transport> = match transport_type.to_lowercase().as_str() {
        "tcp" => {
            info!("Using TCP transport");
            let tcp_transport = TcpTransport::connect(config.server_addr).await?;
            Arc::new(tcp_transport)
        }
        "udp" | _ => {
            info!("Using UDP transport");
            let bind_addr = "0.0.0.0:0".parse()?;
            let udp_transport = UdpTransport::new(bind_addr)?;
            Arc::new(udp_transport)
        }
    };

    let client_id = handshake_async(transport.as_ref(), config.server_addr).await?;
    info!("Client {} ready, tunnel established to {}", client_id, config.server_addr);

    let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>(4096);
    let (transport_tx, transport_rx) = mpsc::channel::<Vec<u8>>(4096);

    let tun_handle = tokio::spawn(
        tun_io_task(
            tun,
            tun_tx,
            transport_rx
        )
    );
    let transport_handle = tokio::spawn(
        transport_io_task(
            Arc::clone(&transport),
            config.server_addr,
            client_id,
            tun_rx,
            transport_tx,
        )
    );
    info!("Client {} is running, press Ctrl+C to stop", client_id);

    tokio::signal::ctrl_c().await?;
    info!("Shutting down client {}...", client_id);

    tun_handle.abort();
    transport_handle.abort();

    Ok(())
}

pub async fn run_client_with_args(
    server: Option<String>,
    tun: Option<String>,
    address: Option<String>,
    netmask: Option<String>,
    mtu: Option<usize>,
    transport: Option<String>,
) -> Result<()> {
    let mut config = ClientConfig::default();
    let transport_type = transport.unwrap_or_else(|| "udp".to_string());

    if let Some(server) = server {
        config.server_addr = server.parse()?;
    }

    if let Some(tun) = tun {
        config.tun_name = tun;
    }

    if let Some(address) = address {
        config.tun_addr = address.parse()?;
    }

    if let Some(netmask) = netmask {
        config.tun_netmask = netmask.parse()?;
    }

    if let Some(mtu) = mtu {
        config.mtu = mtu;
    }

    info!("Client configuration: {:?}", config);
    info!("Transport protocol: {}", transport_type);

    run_client(config, transport_type).await
}
