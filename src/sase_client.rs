use crate::common::{ClientConfig, PacketType, VpnPacket, TUN_MTU};
use anyhow::Result;
use log::{error, info, warn};
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

    // 打印基本信息
    info!("{}: {} {} -> {} ({} bytes)", prefix, proto_name, src_ip, dst_ip, data.len());

    // 打印协议详细信息
    match protocol {
        1 => {
            // ICMP
            if data.len() >= ihl + 8 {
                let icmp_type = data[ihl];
                let icmp_code = data[ihl + 1];
                let checksum = u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]);
                let id = u16::from_be_bytes([data[ihl + 4], data[ihl + 5]]);
                let seq = u16::from_be_bytes([data[ihl + 6], data[ihl + 7]]);

                let type_name = match icmp_type {
                    0 => "Echo Reply",
                    3 => "Destination Unreachable",
                    5 => "Redirect",
                    8 => "Echo Request",
                    11 => "Time Exceeded",
                    _ => "Unknown",
                };
                info!("  └─ ICMP {} | type={}, code={}, checksum={}, id={}, seq={}",
                    type_name, icmp_type, icmp_code, checksum, id, seq);
            }
        }
        6 => {
            // TCP
            if data.len() >= ihl + 20 {
                let src_port = u16::from_be_bytes([data[ihl], data[ihl + 1]]);
                let dst_port = u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]);
                let seq = u32::from_be_bytes([data[ihl + 4], data[ihl + 5], data[ihl + 6], data[ihl + 7]]);
                let ack_num = u32::from_be_bytes([data[ihl + 8], data[ihl + 9], data[ihl + 10], data[ihl + 11]]);
                let flags = data[ihl + 13];
                let syn = (flags & 0x02) != 0;
                let ack_flag = (flags & 0x10) != 0;
                let fin = (flags & 0x01) != 0;
                let rst = (flags & 0x04) != 0;
                let psh = (flags & 0x08) != 0;
                info!("  └─ TCP {} -> {} | SEQ={} ACK={} | flags:{}{}{}{}{}",
                    src_port, dst_port, seq, ack_num,
                    if syn { " SYN" } else { "" },
                    if ack_flag { " ACK" } else { "" },
                    if fin { " FIN" } else { "" },
                    if rst { " RST" } else { "" },
                    if psh { " PSH" } else { "" });
            }
        }
        17 => {
            // UDP
            if data.len() >= ihl + 8 {
                let src_port = u16::from_be_bytes([data[ihl], data[ihl + 1]]);
                let dst_port = u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]);
                let length = u16::from_be_bytes([data[ihl + 4], data[ihl + 5]]);
                info!("  └─ UDP {} -> {} | length={}", src_port, dst_port, length);
            }
        }
        _ => {}
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

async fn tun_io_task(
    mut tun: tun2::AsyncDevice,
    tun_tx: mpsc::Sender<Vec<u8>>,
    mut udp_rx: mpsc::Receiver<Vec<u8>>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut tun_buf = vec![0u8; TUN_MTU];

    info!("TUN I/O task started");

    loop {
        tokio::select! {
            result = udp_rx.recv() => {
                match result {
                    Some(data) => {
                        print_packet_info("WRITE UDP", &data);
                        if let Err(e) = tun.write_all(&data).await {
                            warn!("TUN I/O: Failed to write to TUN: {}", e);
                        }
                    }
                    None => {
                        error!("TUN I/O: Channel disconnected");
                        break;
                    }
                }
            }

            result = tun.read(&mut tun_buf) => {
                match result {
                    Ok(n) => {
                        if n >= 20 {
                            const IP_VERSION: u8 = 0x45;
                            if tun_buf[0] == IP_VERSION {
                                print_packet_info("READ TUN", &tun_buf[..n]);
                                let data = tun_buf[..n].to_vec();
                                if let Err(e) = tun_tx.send(data).await {
                                    error!("TUN I/O: Failed to send to UDP: {}", e);
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("TUN I/O: Error reading from TUN: {}", e);
                        break;
                    }
                }
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

pub async fn run_client(config: ClientConfig) -> Result<()> {
    use tun2::{create_as_async, Configuration};
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

    let tun = create_as_async(&tun_config)?;
    info!("TUN device created: {} -> {}", config.tun_name, config.tun_addr);

    let std_socket = StdUdpSocket::bind("0.0.0.0:0")?;
    std_socket.set_nonblocking(true)?;
    info!("Client bound to {}", std_socket.local_addr()?);

    let socket = UdpSocket::from_std(std_socket)?;
    let socket = Arc::new(socket);

    let client_id = handshake_async(&socket, config.server_addr).await?;
    info!("Client ready, tunnel established...");

    let (tun_to_udp_tx, tun_to_udp_rx) = mpsc::channel::<Vec<u8>>(1000);
    let (udp_to_tun_tx, udp_to_tun_rx) = mpsc::channel::<Vec<u8>>(1000);

    let tun_handle = tokio::spawn(
        tun_io_task(tun, tun_to_udp_tx, udp_to_tun_rx)
    );

    let udp_handle = tokio::spawn(
        udp_io_task(
            Arc::clone(&socket),
            config.server_addr,
            client_id,
            tun_to_udp_rx,
            udp_to_tun_tx,
        )
    );

    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    tun_handle.abort();
    udp_handle.abort();

    Ok(())
}

pub async fn run_client_with_args(
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

    run_client(config).await
}
