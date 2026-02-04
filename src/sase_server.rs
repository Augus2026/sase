use crate::common::{PacketType, ServerConfig, VpnPacket, TUN_MTU};
use anyhow::Result;
use log::{error, info, warn};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

struct Client {
    addr: SocketAddr,
    client_id: u32,
    sequence: u32,
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

/// Run the server with the given configuration
pub fn run_server(config: ServerConfig) -> Result<()> {
    use tun2::{create, Configuration};

    info!("Creating TUN device: {}", config.tun_name);

    let mut tun_config = Configuration::default();

    tun_config
        .tun_name(&config.tun_name)
        .layer(tun2::Layer::L3)
        .mtu(config.mtu as u16)
        .address(config.tun_addr)
        .netmask(config.tun_netmask)
        .up();

    // #[cfg(target_os = "linux")]
    // {
    //     tun_config.platform_specific(|config| {
    //         // Linux-specific configuration
    //     });
    // }

    let tun = create(&tun_config)?;
    info!("TUN device created: {} -> {}", config.tun_name, config.tun_addr);

    // Create UDP socket
    let socket = Arc::new(UdpSocket::bind(&config.bind_addr)?);
    socket.set_nonblocking(true)?;
    info!("Server listening on {}", socket.local_addr()?);

    // Client registry - shared between threads
    let clients = Arc::new(Mutex::new(HashMap::<u32, Client>::new()));
    let next_client_id = Arc::new(Mutex::new(1u32));

    // Create a channel for UDP -> TUN communication
    let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>();

    // Clone for threads
    let tun_reader_socket = Arc::clone(&socket);
    let tun_reader_clients = Arc::clone(&clients);
    let _tun_config = config.clone();

    let udp_reader_socket = Arc::clone(&socket);
    let udp_reader_clients = Arc::clone(&clients);
    let udp_reader_next_client_id = Arc::clone(&next_client_id);
    let udp_tun_tx = tun_tx.clone();
    let _udp_config = config.clone();

    // Spawn TUN reader thread
    let tun_handle = thread::spawn(move || {
        let mut tun = tun;
        let mut tun_buf = vec![0u8; TUN_MTU];

        info!("TUN reader thread started");

        loop {
            // Check for data to write to TUN
            match tun_rx.try_recv() {
                Ok(data) => {
                    if let Err(e) = tun.write_all(&data) {
                        warn!("TUN reader: Failed to write to TUN: {}", e);
                    } else {
                        info!("TUN reader: Wrote {} bytes to TUN", data.len());
                    }
                }
                Err(mpsc::TryRecvError::Empty) => {
                    // No data, continue reading
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    error!("TUN reader: Channel disconnected");
                    break;
                }
            }

            match tun.read(&mut tun_buf) {
                Ok(n) => {
                    info!("TUN reader: Read {} bytes from TUN", n);

                    // Get clients snapshot
                    let clients_map = tun_reader_clients.lock().unwrap();
                    if !clients_map.is_empty() {
                        let packet_data = tun_buf[..n].to_vec();

                        for (_id, client) in clients_map.iter() {
                            let packet = VpnPacket::new(
                                PacketType::Data,
                                client.client_id,
                                client.sequence,
                                n as u16,
                            );

                            let mut send_buf = vec![0u8; VpnPacket::HEADER_SIZE + n];
                            send_buf[..VpnPacket::HEADER_SIZE].copy_from_slice(&packet.to_bytes());
                            send_buf[VpnPacket::HEADER_SIZE..].copy_from_slice(&packet_data);

                            if let Err(e) = tun_reader_socket.send_to(&send_buf, client.addr) {
                                warn!("TUN reader: Failed to send to {}: {}", client.addr, e);
                            }
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    error!("TUN reader: Error reading from TUN: {}", e);
                    break;
                }
            }
        }
    });

    // Spawn UDP reader thread
    let udp_handle = thread::spawn(move || {
        let mut udp_buf = vec![0u8; VpnPacket::HEADER_SIZE + TUN_MTU];

        info!("UDP reader thread started");

        loop {
            match udp_reader_socket.recv_from(&mut udp_buf) {
                Ok((n, src_addr)) => {
                    if n < VpnPacket::HEADER_SIZE {
                        warn!("UDP reader: Received short packet from {}", src_addr);
                        continue;
                    }

                    match VpnPacket::from_bytes(&udp_buf[..n]) {
                        Ok(header) => {
                            info!(
                                "UDP reader: Received type={:?}, client_id={}, seq={}, len={} from {}",
                                header.packet_type, header.client_id, header.sequence,
                                header.length, src_addr
                            );

                            match header.packet_type {
                                PacketType::Handshake => {
                                    // Check if already registered
                                    let is_new = {
                                        let clients_map = udp_reader_clients.lock().unwrap();
                                        !clients_map.values().any(|c| c.addr == src_addr)
                                    };

                                    if is_new {
                                        let client_id = {
                                            let mut next_id = udp_reader_next_client_id.lock().unwrap();
                                            let id = *next_id;
                                            *next_id = next_id.wrapping_add(1);
                                            id
                                        };

                                        let client = Client {
                                            addr: src_addr,
                                            client_id,
                                            sequence: 0,
                                        };

                                        {
                                            let mut clients_map = udp_reader_clients.lock().unwrap();
                                            clients_map.insert(client_id, client);
                                        }

                                        info!("UDP reader: Registered client {} from {}", client_id, src_addr);

                                        // Send handshake response
                                        let response = VpnPacket::new(
                                            PacketType::Handshake,
                                            client_id,
                                            0,
                                            0,
                                        );
                                        let response_buf = response.to_bytes();
                                        if let Err(e) = udp_reader_socket.send_to(&response_buf, src_addr) {
                                            error!("UDP reader: Failed to send handshake: {}", e);
                                        }
                                    } else {
                                        info!("UDP reader: Client {} already registered", src_addr);
                                    }
                                }
                                PacketType::Data => {
                                    info!(
                                        "UDP reader: Received {} bytes of data from client {}",
                                        header.length, header.client_id
                                    );

                                    // Extract the payload (original IP packet)
                                    let payload_start = VpnPacket::HEADER_SIZE;
                                    let payload_end = payload_start + header.length as usize;

                                    if payload_end <= n {
                                        let payload = udp_buf[payload_start..payload_end].to_vec();

                                        // Send to TUN writer via channel
                                        if let Err(e) = udp_tun_tx.send(payload) {
                                            error!("UDP reader: Failed to send to TUN writer: {}", e);
                                        } else {
                                            info!("UDP reader: Sent {} bytes to TUN", header.length);
                                        }
                                    } else {
                                        warn!("UDP reader: Invalid payload length");
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
                                    if let Err(e) = udp_reader_socket.send_to(&response_buf, src_addr) {
                                        warn!("UDP reader: Failed to send keepalive response: {}", e);
                                    }
                                }
                                PacketType::Disconnect => {
                                    let mut clients_map = udp_reader_clients.lock().unwrap();
                                    if let Some(client) = clients_map.remove(&header.client_id) {
                                        info!(
                                            "UDP reader: Client {} disconnected ({})",
                                            header.client_id, client.addr
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("UDP reader: Failed to parse packet from {}: {}", src_addr, e);
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    error!("UDP reader: Error receiving from UDP: {}", e);
                    break;
                }
            }
        }
    });

    info!("Server ready, waiting for connections...");

    // Wait for threads to complete
    tun_handle.join().unwrap();
    udp_handle.join().unwrap();

    Ok(())
}
