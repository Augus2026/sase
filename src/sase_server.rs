use crate::common::{PacketType, ServerConfig, VpnPacket, TUN_MTU};
use anyhow::Result;
use log::{error, info, warn};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::interval;

/// Print packet information for debugging
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

    // Print first 32 bytes in hex
    let hex: String = data.iter().take(32).map(|b| format!("{:02x}", b)).collect();
    info!("{}: Hex: {}", prefix, hex);

    // Print ICMP details if applicable
    if protocol == 1 && data.len() >= ihl + 8 {
        let icmp_type = data[ihl];
        let icmp_code = data[ihl + 1];
        info!("{}: ICMP type={}, code={}", prefix, icmp_type, icmp_code);
    }
}

#[derive(Clone)]
struct Client {
    addr: SocketAddr,
    client_id: u32,
    sequence: u32,
}

/// TUN reader task - runs in blocking thread
fn tun_reader_thread(
    mut tun: impl Read + Write + 'static,
    tun_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    mut udp_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) {
    let mut tun_buf = vec![0u8; TUN_MTU];
    let mut counter = 0usize;

    info!("TUN reader thread started");

    loop {
        // Check for data to write to TUN
        match udp_rx.try_recv() {
            Ok(data) => {
                print_packet_info("Client->TUN", &data);
                if let Err(e) = tun.write_all(&data) {
                    warn!("TUN I/O: Failed to write to TUN: {}", e);
                }
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                error!("TUN reader: Channel disconnected");
                break;
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
        }

        // Read from TUN
        match tun.read(&mut tun_buf) {
            Ok(n) => {
                counter += 1;
                if counter % 100 == 0 {
                    info!("TUN I/O: Active - broadcasting {} bytes", n);
                }

                print_packet_info("TUN->Client", &tun_buf[..n]);

                // Send to UDP task
                let data = tun_buf[..n].to_vec();
                if let Err(e) = tun_tx.blocking_send(data) {
                    error!("TUN reader: Failed to send to UDP: {}", e);
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                error!("TUN I/O: Error reading from TUN: {}", e);
                break;
            }
        }
    }
}

/// UDP I/O task using tokio::select!
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
            // Receive data from clients
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
                                        // Check if already registered
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

                                            // Send handshake response
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

                                            // Send to TUN writer
                                            if let Err(e) = tun_tx.send(payload).await {
                                                error!("Failed to send to TUN writer: {}", e);
                                                break;
                                            }
                                        } else {
                                            warn!("Invalid payload length");
                                        }
                                    }
                                    PacketType::KeepAlive => {
                                        // Respond to keep-alive
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
                                    _ => {
                                        info!("Received packet type: {:?}", header.packet_type);
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

            // Send data to clients (from TUN)
            result = tun_rx.recv() => {
                match result {
                    Some(data) => {
                        let clients_map = clients.lock().await;
                        if !clients_map.is_empty() {
                            // Broadcast to all clients
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

/// Run the server with the given configuration
pub fn run_server(config: ServerConfig) -> Result<()> {
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

    // Create async runtime
    let rt = tokio::runtime::Runtime::new()?;

    // Block on async main
    rt.block_on(async move {
        // Bind UDP socket
        let std_socket = StdUdpSocket::bind(&config.bind_addr)?;
        std_socket.set_nonblocking(true)?;
        info!("Server listening on {}", std_socket.local_addr()?);

        let socket = UdpSocket::from_std(std_socket)?;
        let socket = Arc::new(socket);

        // Create channels
        let (tun_to_udp_tx, tun_to_udp_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);
        let (udp_to_tun_tx, udp_to_tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);

        // Client registry
        let clients = Arc::new(Mutex::new(HashMap::<u32, Client>::new()));

        // Spawn TUN reader in blocking thread
        let tun_handle = tokio::task::spawn_blocking(move || {
            tun_reader_thread(tun, tun_to_udp_tx, udp_to_tun_rx);
        });

        // Spawn UDP I/O task
        let udp_handle = tokio::spawn(udp_io_task(
            Arc::clone(&socket),
            Arc::clone(&clients),
            tun_to_udp_rx,
            udp_to_tun_tx,
        ));

        info!("Server ready, waiting for connections...");

        // Wait for Ctrl+C
        tokio::signal::ctrl_c().await?;
        info!("Shutting down...");

        // Cancel tasks
        tun_handle.abort();
        udp_handle.abort();

        Ok::<(), anyhow::Error>(())
    })?;

    Ok(())
}

/// Run the server with the specified arguments
pub fn run_server_with_args(
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

    run_server(config)
}
