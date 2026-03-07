use crate::common::{ClientConfig, tun_io_task, print_packet_info};
use crate::transport::{TransportTrait, TcpTransport, UdpTransport};
use crate::codec::{Message, MessageType};
use anyhow::Result;
use log::{error, info, warn};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{interval, sleep};
use tun2::{create_as_async, Configuration};

async fn handshake_async(
    transport: &mut impl TransportTrait<Error = std::io::Error>,
    server_addr: std::net::SocketAddr,
) -> Result<u32> {
    info!("Connecting to server at {}", server_addr);
    let handshake_message = Message::handshake(vec![]);
    let mut retry_delay = Duration::from_secs(1);
    let max_retry_delay = Duration::from_secs(300);
    let mut attempt = 0u32;

    loop {
        attempt += 1;
        info!("Handshake attempt {} to {}", attempt, server_addr);

        transport.send(handshake_message.clone(), server_addr).await?;
        info!("Handshake sent to {}", server_addr);

        let timeout = sleep(Duration::from_secs(5));
        tokio::pin!(timeout);

        tokio::select! {
            result = transport.next() => {
                match result {
                    Some(Ok((msg, addr))) => {
                        if addr == server_addr {
                            if msg.message_type == MessageType::Handshake as u8 {
                                if msg.data.len() >= 4 {
                                    let client_id = u32::from_be_bytes([msg.data[0], msg.data[1], msg.data[2], msg.data[3]]);
                                    info!("Connected! Client ID: {}", client_id);
                                    return Ok(client_id);
                                } else {
                                    info!("Invalid handshake response: missing client_id");
                                }
                            } else {
                                info!("Unexpected packet type during handshake: {}", msg.message_type);
                            }
                        }
                    }
                    Some(Err(e)) => {
                        info!("Error during handshake attempt {}: {}", attempt, e);
                    }
                    None => {}
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

async fn transport_io_task<T>(
    mut transport: T,
    server_addr: std::net::SocketAddr,
    client_id: u32,
    mut tun_rx: mpsc::Receiver<Vec<u8>>,
    transport_tx: mpsc::Sender<Vec<u8>>,
)
where
    T: TransportTrait<Error = std::io::Error>,
{
    let mut keepalive_interval = interval(Duration::from_secs(1));
    info!("Transport I/O task started for client {}", client_id);

    loop {
        tokio::select! {
            result = transport.next() => {
                match result {
                    Some(Ok((msg, src_addr))) => {
                        if src_addr != server_addr {
                            info!("Transport: Received packet from unexpected address: {}", src_addr);
                            continue;
                        }

                        match msg.message_type {
                            t if t == MessageType::Data as u8 => {
                                // Data message contains raw IP packet
                                print_packet_info("[transport recv]", &msg.data);
                                if let Err(e) = transport_tx.send(msg.data).await {
                                    error!("Transport: Failed to send to TUN: {}", e);
                                    break;
                                }
                            }
                            t if t == MessageType::KeepAlive as u8 => {
                                info!("Keepalive received from server");
                            }
                            t if t == MessageType::Disconnect as u8 => {
                                warn!("Server disconnected");
                                break;
                            }
                            _ => {
                                info!("Transport: Unknown message type: {}", msg.message_type);
                            }
                        }
                    }
                    Some(Err(e)) => {
                        error!("Transport: Error receiving: {}", e);
                        break;
                    }
                    None => {
                        break;
                    }
                }
            }

            result = tun_rx.recv() => {
                match result {
                    Some(data) => {
                        print_packet_info("[transport send]", &data);
                        let message = Message::data(data);
                        if let Err(e) = transport.send(message, server_addr).await {
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
                let message = Message::keepalive(vec![]);
                if let Err(e) = transport.send(message, server_addr).await {
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

    match transport_type.to_lowercase().as_str() {
        "tcp" => {
            info!("Using TCP transport");
            let mut transport = TcpTransport::connect(config.server_addr.to_string().as_str()).await?;
            let client_id = handshake_async(&mut transport, config.server_addr).await?;

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
                    transport,
                    config.server_addr,
                    client_id,
                    tun_rx,
                    transport_tx,
                )
            );

            tokio::signal::ctrl_c().await?;
            info!("Shutting down client {}...", client_id);

            tun_handle.abort();
            transport_handle.abort();

            return Ok(());
        }
        "udp" | _ => {
            info!("Using UDP transport");
            let mut transport = UdpTransport::bind("0.0.0.0:0").await?;
            let client_id = handshake_async(&mut transport, config.server_addr).await?;

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
                    transport,
                    config.server_addr,
                    client_id,
                    tun_rx,
                    transport_tx,
                )
            );

            tokio::signal::ctrl_c().await?;
            info!("Shutting down client {}...", client_id);

            tun_handle.abort();
            transport_handle.abort();

            return Ok(());
        }
    };
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
