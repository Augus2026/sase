use crate::common::{ClientConfig, PacketType, VpnPacket, TUN_MTU};
use anyhow::Result;
use log::{error, info, warn};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{interval, sleep};

#[allow(dead_code)]
fn print_packet_info(prefix: &str, data: &[u8]) {
    if data.len() < 20 {
        info!("{}: Packet too short ({:?} bytes)", prefix, data);
        return;
    }

    let ihl = ((data[0] & 0x0F) as usize) * 4;
    let protocol = data[9];
    let src_ip = std::net::Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = std::net::Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    let proto_name = match protocol {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        _ => "Other",
    };

    info!("{}: {} {} -> {} ({} bytes)", prefix, proto_name, src_ip, dst_ip, data.len());

    if protocol == 1 && data.len() >= ihl + 8 {
        let icmp_type = data[ihl];
        let icmp_code = data[ihl + 1];
        info!("{}: ICMP type={}, code={}", prefix, icmp_type, icmp_code);
    }
}

async fn handshake_async(socket: &UdpSocket, server_addr: std::net::SocketAddr) -> Result<u32> {
    info!("Connecting to server at {}", server_addr);

    let handshake_packet = VpnPacket::new(PacketType::Handshake, 0, 0, 0);
    let handshake_buf = handshake_packet.to_bytes();

    socket.send_to(&handshake_buf, server_addr).await?;
    info!("Handshake sent to {}", server_addr);

    let timeout = sleep(Duration::from_secs(5));
    tokio::pin!(timeout);

    let mut recv_buf = [0u8; VpnPacket::HEADER_SIZE];

    loop {
        tokio::select! {
            result = socket.recv_from(&mut recv_buf) => {
                match result {
                    Ok((n, addr)) => {
                        if addr == server_addr {
                            match VpnPacket::from_bytes(&recv_buf[..n]) {
                                Ok(header) if header.packet_type == PacketType::Handshake => {
                                    info!("Connected! Client ID: {}", header.client_id);
                                    return Ok(header.client_id);
                                }
                                _ => {
                                    warn!("Unexpected packet during handshake");
                                    continue;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Error during handshake: {}", e);
                        return Err(e.into());
                    }
                }
            }
            _ = &mut timeout => {
                error!("Handshake timeout");
                anyhow::bail!("Handshake timeout");
            }
        }
    }
}

fn tun_reader_thread(
    mut tun: impl Read + Write + 'static,
    tun_tx: mpsc::Sender<Vec<u8>>,
    mut udp_rx: mpsc::Receiver<Vec<u8>>,
    local_addr: std::net::Ipv4Addr,
) {
    let mut tun_buf = vec![0u8; TUN_MTU];
    let mut sequence = 0u32;

    info!("TUN reader thread started");

    loop {
        match udp_rx.try_recv() {
            Ok(data) => {
                if let Err(e) = tun.write_all(&data) {
                    warn!("TUN I/O: Failed to write to TUN: {}", e);
                }
            }
            Err(mpsc::error::TryRecvError::Disconnected) => {
                error!("TUN reader: Channel disconnected");
                break;
            }
            Err(mpsc::error::TryRecvError::Empty) => {}
        }

        match tun.read(&mut tun_buf) {
            Ok(n) => {
                if n >= 20 {
                    const IP_VERSION: u8 = 0x45;
                    if tun_buf[0] == IP_VERSION {
                        let src_addr = std::net::Ipv4Addr::new(tun_buf[12], tun_buf[13], tun_buf[14], tun_buf[15]);

                        if src_addr == local_addr {
                            if sequence % 1000 == 0 {
                                info!("TUN I/O: Forwarding {} bytes from {} (total: {})", n, src_addr, sequence);
                            }
                            sequence += 1;

                            let data = tun_buf[..n].to_vec();
                            if let Err(e) = tun_tx.blocking_send(data) {
                                error!("TUN reader: Failed to send to UDP: {}", e);
                                break;
                            }
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => {
                error!("TUN I/O: Error reading from TUN: {}", e);
                break;
            }
        }
    }
}

async fn udp_io_task(
    socket: Arc<UdpSocket>,
    server_addr: std::net::SocketAddr,
    client_id: u32,
    mut tun_rx: mpsc::Receiver<Vec<u8>>,
    tun_tx: mpsc::Sender<Vec<u8>>,
) {
    let mut udp_buf = vec![0u8; VpnPacket::HEADER_SIZE + TUN_MTU];
    let mut keepalive_interval = interval(Duration::from_secs(10));
    let mut sequence = 0u32;

    info!("UDP I/O task started");

    loop {
        tokio::select! {
            result = socket.recv_from(&mut udp_buf) => {
                match result {
                    Ok((n, src_addr)) => {
                        if src_addr != server_addr {
                            warn!("UDP: Received packet from unexpected address: {}", src_addr);
                            continue;
                        }

                        if n < VpnPacket::HEADER_SIZE {
                            warn!("UDP: Received short packet");
                            continue;
                        }

                        match VpnPacket::from_bytes(&udp_buf[..n]) {
                            Ok(header) => {
                                if header.client_id != client_id {
                                    continue;
                                }

                                match header.packet_type {
                                    PacketType::Data => {
                                        let payload_start = VpnPacket::HEADER_SIZE;
                                        let payload_end = payload_start + header.length as usize;

                                        if payload_end <= n {
                                            let payload = udp_buf[payload_start..payload_end].to_vec();
                                            if let Err(e) = tun_tx.send(payload).await {
                                                error!("UDP: Failed to send to TUN: {}", e);
                                                break;
                                            }
                                        }
                                    }
                                    PacketType::KeepAlive => {}
                                    PacketType::Disconnect => {
                                        error!("UDP: Server disconnected");
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                            Err(e) => {
                                warn!("UDP: Failed to parse packet: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("UDP: Error receiving: {}", e);
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

                        if let Err(e) = socket.send_to(&send_buf, server_addr).await {
                            warn!("UDP: Failed to send to server: {}", e);
                        }
                    }
                    None => {
                        error!("UDP: Channel disconnected");
                        break;
                    }
                }
            }

            _ = keepalive_interval.tick() => {
                let packet = VpnPacket::new(PacketType::KeepAlive, client_id, sequence, 0);
                sequence = sequence.wrapping_add(1);
                let buf = packet.to_bytes();

                if let Err(e) = socket.send_to(&buf, server_addr).await {
                    warn!("Keepalive: Failed to send: {}", e);
                } else {
                    info!("Keepalive: Sent");
                }
            }
        }
    }
}

pub fn run_client(config: ClientConfig) -> Result<()> {
    use tun2::{create, Configuration};
    use std::net::UdpSocket as StdUdpSocket;

    info!("Creating TUN device: {}", config.tun_name);

    let mut tun_config = Configuration::default();
    tun_config
        .tun_name(&config.tun_name)
        .layer(tun2::Layer::L3)
        .mtu(config.mtu as u16)
        .address(config.tun_addr)
        .netmask(config.tun_netmask)
        .up();

    let tun = create(&tun_config)?;
    info!("TUN device created: {} -> {}", config.tun_name, config.tun_addr);

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let std_socket = StdUdpSocket::bind("0.0.0.0:0")?;
        std_socket.set_nonblocking(true)?;
        info!("Client bound to {}", std_socket.local_addr()?);

        let socket = UdpSocket::from_std(std_socket)?;
        let socket = Arc::new(socket);

        let client_id = handshake_async(&socket, config.server_addr).await?;
        info!("Client ready, tunnel established...");

        let (tun_to_udp_tx, tun_to_udp_rx) = mpsc::channel::<Vec<u8>>(1000);
        let (udp_to_tun_tx, udp_to_tun_rx) = mpsc::channel::<Vec<u8>>(1000);
        let local_addr = config.tun_addr;

        let tun_handle = tokio::task::spawn_blocking(move || {
            tun_reader_thread(tun, tun_to_udp_tx, udp_to_tun_rx, local_addr);
        });

        let udp_handle = tokio::spawn(udp_io_task(
            Arc::clone(&socket),
            config.server_addr,
            client_id,
            tun_to_udp_rx,
            udp_to_tun_tx,
        ));

        tokio::signal::ctrl_c().await?;
        info!("Shutting down...");

        tun_handle.abort();
        udp_handle.abort();

        Ok::<(), anyhow::Error>(())
    })?;

    Ok(())
}

pub fn run_client_with_args(
    server: Option<String>,
    tun: Option<String>,
    address: Option<String>,
    netmask: Option<String>,
    mtu: Option<usize>,
) -> Result<()> {
    let mut config = ClientConfig::default();

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

    info!("Configuration: {:?}", config);

    run_client(config)
}
