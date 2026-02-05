use crate::common::{PacketType, ServerConfig, VpnPacket, TUN_MTU};
use anyhow::Result;
use log::{error, info, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

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

#[derive(Clone)]
struct Client {
    addr: SocketAddr,
    client_id: u32,
    sequence: u32,
}

async fn tun_io_task(
    mut tun: tun2::AsyncDevice,
    tun_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    mut udp_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut tun_buf = vec![0u8; TUN_MTU];

    info!("TUN I/O task started");

    loop {
        tokio::select! {
            result = udp_rx.recv() => {
                match result {
                    Some(data) => {
                        print_packet_info("[tun write]", &data);
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
                        let data = tun_buf[..n].to_vec();
                        print_packet_info("[tun read]", &data);
                        if let Err(e) = tun_tx.send(data).await {
                            error!("TUN I/O: Failed to send to UDP: {}", e);
                            break;
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
    clients: Arc<Mutex<HashMap<u32, Client>>>,
    mut tun_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    tun_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    let mut udp_buf = vec![0u8; VpnPacket::HEADER_SIZE + TUN_MTU];
    let mut next_client_id = 1u32;

    info!("UDP I/O task started");

    loop {
        tokio::select! {
            result = socket.recv_from(&mut udp_buf) => {
                match result {
                    Ok((n, src_addr)) => {
                        if n < VpnPacket::HEADER_SIZE {
                            warn!("UDP: Received short packet from {}", src_addr);
                            continue;
                        }

                        match VpnPacket::from_bytes(&udp_buf[..n]) {
                            Ok(header) => {
                                match header.packet_type {
                                    PacketType::Handshake => {
                                        let is_new = {
                                            let clients_map = clients.lock().await;
                                            !clients_map.values().any(|c| c.addr == src_addr)
                                        };

                                        if is_new {
                                            let client = Client {
                                                addr: src_addr,
                                                client_id: next_client_id,
                                                sequence: 0,
                                            };

                                            {
                                                let mut clients_map = clients.lock().await;
                                                clients_map.insert(next_client_id, client.clone());
                                            }

                                            info!("Registered client {} from {}", next_client_id, src_addr);

                                            let response = VpnPacket::new(
                                                PacketType::Handshake,
                                                next_client_id,
                                                0,
                                                0,
                                            );
                                            let response_buf = response.to_bytes();
                                            if let Err(e) = socket.send_to(&response_buf, src_addr).await {
                                                error!("Failed to send handshake: {}", e);
                                            }

                                            next_client_id = next_client_id.wrapping_add(1);
                                        }
                                    }
                                    PacketType::Data => {
                                        let payload_start = VpnPacket::HEADER_SIZE;
                                        let payload_end = payload_start + header.length as usize;

                                        if payload_end <= n {
                                            let payload = udp_buf[payload_start..payload_end].to_vec();
                                            print_packet_info("[udp read]", &payload);
                                            if let Err(e) = tun_tx.send(payload).await {
                                                error!("Failed to send to TUN writer: {}", e);
                                                break;
                                            }
                                        } else {
                                            warn!("Invalid payload length");
                                        }
                                    }
                                    PacketType::KeepAlive => {
                                        let response = VpnPacket::new(
                                            PacketType::KeepAlive,
                                            header.client_id,
                                            header.sequence,
                                            0,
                                        );
                                        let response_buf = response.to_bytes();
                                        if let Err(e) = socket.send_to(&response_buf, src_addr).await {
                                            warn!("Failed to send keepalive response: {}", e);
                                        }
                                    }
                                    PacketType::Disconnect => {
                                        let mut clients_map = clients.lock().await;
                                        if let Some(client) = clients_map.remove(&header.client_id) {
                                            info!("Client {} disconnected ({})", header.client_id, client.addr);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to parse packet from {}: {}", src_addr, e);
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
                        let clients_map = clients.lock().await;
                        if !clients_map.is_empty() {
                            for (_id, client) in clients_map.iter() {
                                let packet = VpnPacket::new(
                                    PacketType::Data,
                                    client.client_id,
                                    client.sequence,
                                    data.len() as u16,
                                );

                                let mut send_buf = vec![0u8; VpnPacket::HEADER_SIZE + data.len()];
                                send_buf[..VpnPacket::HEADER_SIZE].copy_from_slice(&packet.to_bytes());
                                send_buf[VpnPacket::HEADER_SIZE..].copy_from_slice(&data);

                                print_packet_info("[udp write]", &send_buf);
                                if let Err(e) = socket.send_to(&send_buf, client.addr).await {
                                    warn!("Failed to send to {}: {}", client.addr, e);
                                }
                            }
                        }
                    }
                    None => {
                        error!("UDP: Channel disconnected");
                        break;
                    }
                }
            }
        }
    }
}

pub async fn run_server(config: ServerConfig) -> Result<()> {
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

    let std_socket = StdUdpSocket::bind(&config.bind_addr)?;
    std_socket.set_nonblocking(true)?;
    info!("Server listening on {}", std_socket.local_addr()?);

    let socket = UdpSocket::from_std(std_socket)?;
    let socket = Arc::new(socket);

    let (tun_to_udp_tx, tun_to_udp_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1000);
    let (udp_to_tun_tx, udp_to_tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1000);

    let clients = Arc::new(Mutex::new(HashMap::<u32, Client>::new()));
    let tun_handle = tokio::spawn(tun_io_task(tun, tun_to_udp_tx, udp_to_tun_rx));

    let udp_handle = tokio::spawn(udp_io_task(
        Arc::clone(&socket),
        Arc::clone(&clients),
        tun_to_udp_rx,
        udp_to_tun_tx,
    ));

    info!("Server ready, waiting for connections...");

    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    tun_handle.abort();
    udp_handle.abort();

    Ok(())
}

pub async fn run_server_with_args(
    bind: Option<String>,
    tun: Option<String>,
    address: Option<String>,
    netmask: Option<String>,
    mtu: Option<usize>,
) -> Result<()> {
    let mut config = ServerConfig::default();

    if let Some(bind) = bind {
        config.bind_addr = bind.parse()?;
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

    run_server(config).await
}
