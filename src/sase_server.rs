use crate::common::{PacketType, ServerConfig, VpnPacket, TUN_MTU};
use anyhow::Result;
use log::{error, info, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::sync::mpsc::{self, Receiver, Sender};
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

/// TUN I/O thread: handles both reading from and writing to TUN device
fn tun_io_thread(
    mut tun: impl std::io::Read + std::io::Write,
    tun_rx: Receiver<Vec<u8>>,
    socket: Arc<UdpSocket>,
    clients: Arc<Mutex<HashMap<u32, Client>>>,
) {
    let mut tun_buf = vec![0u8; TUN_MTU];

    info!("TUN I/O thread started");

    loop {
        // Check for data to write to TUN
        match tun_rx.try_recv() {
            Ok(data) => {
                if let Err(e) = tun.write_all(&data) {
                    warn!("TUN I/O: Failed to write to TUN: {}", e);
                } else {
                    info!("TUN I/O: Wrote {} bytes to TUN", data.len());
                }
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                error!("TUN I/O: Channel disconnected");
                break;
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }

        // Read from TUN and broadcast to all clients
        match tun.read(&mut tun_buf) {
            Ok(n) => {
                // Only log occasionally to reduce spam
                static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
                if COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 100 == 0 {
                    info!("TUN I/O: Active - broadcasting {} bytes", n);
                }

                let clients_map = clients.lock().unwrap();
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

                        if let Err(e) = socket.send_to(&send_buf, client.addr) {
                            warn!("TUN I/O: Failed to send to {}: {}", client.addr, e);
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                error!("TUN I/O: Error reading from TUN: {}", e);
                break;
            }
        }
    }
}

/// Handle client handshake
fn handle_handshake(
    socket: &UdpSocket,
    src_addr: SocketAddr,
    clients: &Arc<Mutex<HashMap<u32, Client>>>,
    next_client_id: &Arc<Mutex<u32>>,
) {
    // Check if already registered
    let is_new = {
        let clients_map = clients.lock().unwrap();
        !clients_map.values().any(|c| c.addr == src_addr)
    };

    if is_new {
        let client_id = {
            let mut next_id = next_client_id.lock().unwrap();
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
            let mut clients_map = clients.lock().unwrap();
            clients_map.insert(client_id, client);
        }

        info!("Registered client {} from {}", client_id, src_addr);

        // Send handshake response
        let response = VpnPacket::new(PacketType::Handshake, client_id, 0, 0);
        let response_buf = response.to_bytes();
        if let Err(e) = socket.send_to(&response_buf, src_addr) {
            error!("Failed to send handshake: {}", e);
        }
    } else {
        info!("Client {} already registered", src_addr);
    }
}

/// Handle data packet from client
fn handle_data_packet(
    header: &VpnPacket,
    udp_buf: &[u8],
    n: usize,
    tun_tx: &Sender<Vec<u8>>,
) {
    let payload_start = VpnPacket::HEADER_SIZE;
    let payload_end = payload_start + header.length as usize;

    if payload_end <= n {
        let payload = udp_buf[payload_start..payload_end].to_vec();

        if let Err(e) = tun_tx.send(payload) {
            error!("Failed to send to TUN writer: {}", e);
        }
        // Removed verbose logging
    } else {
        warn!("Invalid payload length");
    }
}

/// UDP reader thread: receives data from clients and handles packets
fn udp_reader_thread(
    socket: Arc<UdpSocket>,
    clients: Arc<Mutex<HashMap<u32, Client>>>,
    next_client_id: Arc<Mutex<u32>>,
    tun_tx: Sender<Vec<u8>>,
) {
    let mut udp_buf = vec![0u8; VpnPacket::HEADER_SIZE + TUN_MTU];

    info!("UDP reader thread started");

    loop {
        match socket.recv_from(&mut udp_buf) {
            Ok((n, src_addr)) => {
                if n < VpnPacket::HEADER_SIZE {
                    warn!("Received short packet from {}", src_addr);
                    continue;
                }

                match VpnPacket::from_bytes(&udp_buf[..n]) {
                    Ok(header) => {
                        // Only log important events
                        if header.packet_type != PacketType::Data {
                            info!(
                                "Received type={:?}, client_id={}, seq={}, len={} from {}",
                                header.packet_type, header.client_id, header.sequence, header.length, src_addr
                            );
                        }

                        match header.packet_type {
                            PacketType::Handshake => {
                                handle_handshake(&socket, src_addr, &clients, &next_client_id);
                            }
                            PacketType::Data => {
                                handle_data_packet(&header, &udp_buf, n, &tun_tx);
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
                                if let Err(e) = socket.send_to(&response_buf, src_addr) {
                                    warn!("Failed to send keepalive response: {}", e);
                                }
                            }
                            PacketType::Disconnect => {
                                let mut clients_map = clients.lock().unwrap();
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
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                error!("Error receiving from UDP: {}", e);
                break;
            }
        }
    }
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

    let tun = create(&tun_config)?;
    info!("TUN device created: {} -> {}", config.tun_name, config.tun_addr);

    // Create UDP socket
    let socket = Arc::new(UdpSocket::bind(&config.bind_addr)?);
    socket.set_nonblocking(true)?;
    info!("Server listening on {}", socket.local_addr()?);

    // Client registry - shared between threads
    let clients = Arc::new(Mutex::new(HashMap::<u32, Client>::new()));
    let next_client_id = Arc::new(Mutex::new(1u32));

    // Create channel for UDP -> TUN communication
    let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>();

    // Spawn threads
    let tun_handle = thread::spawn({
        let socket = Arc::clone(&socket);
        let clients = Arc::clone(&clients);

        move || {
            tun_io_thread(tun, tun_rx, socket, clients);
        }
    });

    let udp_handle = thread::spawn({
        let socket = Arc::clone(&socket);
        let clients = Arc::clone(&clients);
        let next_client_id = Arc::clone(&next_client_id);

        move || {
            udp_reader_thread(socket, clients, next_client_id, tun_tx);
        }
    });

    info!("Server ready, waiting for connections...");

    // Wait for threads to complete
    tun_handle.join().unwrap();
    udp_handle.join().unwrap();

    Ok(())
}
