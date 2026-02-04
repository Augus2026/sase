use crate::common::{ClientConfig, PacketType, VpnPacket, TUN_MTU};
use anyhow::Result;
use log::{error, info, warn};
use std::io::{Read, Write};
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Run the client with the specified arguments
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

/// Run the client with the given configuration
pub fn run_client(config: ClientConfig) -> Result<()> {
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

    let tun = create(&tun_config)?;
    info!("TUN device created: {} -> {}", config.tun_name, config.tun_addr);

    // Create UDP socket
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0")?);
    socket.set_nonblocking(true)?;
    info!("Client bound to {}", socket.local_addr()?);

    // Shared state
    let client_id = Arc::new(AtomicU32::new(0));
    let sequence = Arc::new(AtomicU32::new(0));
    let connected = Arc::new(AtomicBool::new(false));

    // Perform handshake
    info!("Connecting to server at {}", config.server_addr);

    let handshake_packet = VpnPacket::new(PacketType::Handshake, 0, 0, 0);
    let handshake_buf = handshake_packet.to_bytes();

    socket.send_to(&handshake_buf, config.server_addr)?;
    info!("Handshake sent to {}", config.server_addr);

    // Wait for handshake response
    let mut resp_buf = [0u8; VpnPacket::HEADER_SIZE];
    let timeout_start = std::time::Instant::now();
    let timeout_duration = Duration::from_secs(5);

    loop {
        match socket.recv_from(&mut resp_buf) {
            Ok((n, addr)) => {
                if addr == config.server_addr {
                    match VpnPacket::from_bytes(&resp_buf[..n]) {
                        Ok(header) if header.packet_type == PacketType::Handshake => {
                            info!("Connected! Client ID: {}", header.client_id);
                            client_id.store(header.client_id, Ordering::SeqCst);
                            connected.store(true, Ordering::SeqCst);
                            break;
                        }
                        _ => {
                            warn!("Unexpected packet during handshake");
                            continue;
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No data yet
            }
            Err(e) => {
                error!("Error during handshake: {}", e);
                return Err(e.into());
            }
        }

        if timeout_start.elapsed() > timeout_duration {
            error!("Handshake timeout");
            anyhow::bail!("Handshake timeout");
        }

        thread::sleep(Duration::from_millis(100));
    }

    info!("Client ready, tunnel established...");

    // Create a channel for UDP -> TUN communication
    let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>();

    // Clone shared state for threads
    let tun_reader_socket = Arc::clone(&socket);
    let tun_reader_client_id = Arc::clone(&client_id);
    let tun_reader_sequence = Arc::clone(&sequence);
    let tun_reader_connected = Arc::clone(&connected);
    let tun_config = config.clone();

    let udp_reader_socket = Arc::clone(&socket);
    let udp_reader_client_id = Arc::clone(&client_id);
    let udp_reader_connected = Arc::clone(&connected);
    let udp_tun_tx = tun_tx.clone();
    let udp_config = config.clone();

    let keepalive_socket = Arc::clone(&socket);
    let keepalive_client_id = Arc::clone(&client_id);
    let keepalive_sequence = Arc::clone(&sequence);
    let keepalive_connected = Arc::clone(&connected);
    let keepalive_config = config.clone();

    // Spawn TUN reader thread
    let tun_handle = thread::spawn(move || {
        let mut tun = tun;
        let mut tun_buf = vec![0u8; TUN_MTU];

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
                Ok(n) if tun_reader_connected.load(Ordering::SeqCst) => {
                    info!("TUN reader: Read {} bytes from TUN", n);

                    let current_client_id = tun_reader_client_id.load(Ordering::SeqCst);
                    let current_sequence = tun_reader_sequence.fetch_add(1, Ordering::SeqCst);

                    let packet = VpnPacket::new(PacketType::Data, current_client_id, current_sequence, n as u16);

                    let mut send_buf = vec![0u8; VpnPacket::HEADER_SIZE + n];
                    send_buf[..VpnPacket::HEADER_SIZE].copy_from_slice(&packet.to_bytes());
                    send_buf[VpnPacket::HEADER_SIZE..].copy_from_slice(&tun_buf[..n]);

                    if let Err(e) = tun_reader_socket.send_to(&send_buf, tun_config.server_addr) {
                        warn!("TUN reader: Failed to send to server: {}", e);
                    }
                }
                Ok(_) => {}
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

        loop {
            match udp_reader_socket.recv_from(&mut udp_buf) {
                Ok((n, src_addr)) => {
                    if src_addr != udp_config.server_addr {
                        warn!("UDP reader: Received packet from unexpected address: {}", src_addr);
                        continue;
                    }

                    if n < VpnPacket::HEADER_SIZE {
                        warn!("UDP reader: Received short packet from {}", src_addr);
                        continue;
                    }

                    match VpnPacket::from_bytes(&udp_buf[..n]) {
                        Ok(header) => {
                            if header.client_id != udp_reader_client_id.load(Ordering::SeqCst) {
                                warn!("UDP reader: Packet for different client ID");
                                continue;
                            }

                            info!(
                                "UDP reader: Received type={:?}, seq={}, len={}",
                                header.packet_type, header.sequence, header.length
                            );

                            match header.packet_type {
                                PacketType::Data => {
                                    info!("UDP reader: Received {} bytes of data from server", header.length);

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
                                    info!("UDP reader: Received keepalive from server");
                                }
                                PacketType::Disconnect => {
                                    error!("UDP reader: Server disconnected");
                                    udp_reader_connected.store(false, Ordering::SeqCst);
                                    break;
                                }
                                _ => {
                                    info!("UDP reader: Received packet type: {:?}", header.packet_type);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("UDP reader: Failed to parse packet: {}", e);
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

    // Keepalive thread
    let keepalive_handle = thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(10));

            if keepalive_connected.load(Ordering::SeqCst) {
                let current_client_id = keepalive_client_id.load(Ordering::SeqCst);
                let current_sequence = keepalive_sequence.load(Ordering::SeqCst);

                let packet = VpnPacket::new(PacketType::KeepAlive, current_client_id, current_sequence, 0);
                let buf = packet.to_bytes();

                if let Err(e) = keepalive_socket.send_to(&buf, keepalive_config.server_addr) {
                    warn!("Keepalive: Failed to send keepalive: {}", e);
                } else {
                    info!("Keepalive: Sent keepalive to server");
                }
            }
        }
    });

    // Wait for threads to complete
    tun_handle.join().unwrap();
    udp_handle.join().unwrap();
    keepalive_handle.join().unwrap();

    Ok(())
}
