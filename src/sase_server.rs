use crate::common::{PacketType, ServerConfig, VpnPacket, TUN_MTU};
use anyhow::Result;
use log::{error, info, warn};
use std::collections::HashMap;
use std::io::Read;
use std::net::SocketAddr;
use std::net::UdpSocket;
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

    let mut tun = create(&tun_config)?;
    info!("TUN device created: {} -> {}", config.tun_name, config.tun_addr);

    // Create UDP socket
    let socket = UdpSocket::bind(&config.bind_addr)?;
    socket.set_nonblocking(true)?;
    info!("Server listening on {}", socket.local_addr()?);

    // Client registry
    let mut clients: HashMap<u32, Client> = HashMap::new();
    let mut next_client_id: u32 = 1;

    let mut tun_buf = vec![0u8; TUN_MTU];
    let mut udp_buf = vec![0u8; VpnPacket::HEADER_SIZE + TUN_MTU];

    info!("Server ready, waiting for connections...");

    loop {
        // Read from TUN and forward to clients
        match tun.read(&mut tun_buf) {
            Ok(n) => {
                info!("Read {} bytes from TUN", n);

                if !clients.is_empty() {
                    let packet_data = &tun_buf[..n];

                    for (_id, client) in clients.iter_mut() {
                        let packet = VpnPacket::new(
                            PacketType::Data,
                            client.client_id,
                            client.sequence,
                            n as u16,
                        );

                        let mut send_buf = vec![0u8; VpnPacket::HEADER_SIZE + n];
                        send_buf[..VpnPacket::HEADER_SIZE].copy_from_slice(&packet.to_bytes());
                        send_buf[VpnPacket::HEADER_SIZE..].copy_from_slice(packet_data);

                        if let Err(e) = socket.send_to(&send_buf, client.addr) {
                            warn!("Failed to send to {}: {}", client.addr, e);
                        } else {
                            client.sequence += 1;
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No data available, continue
            }
            Err(e) => {
                error!("Error reading from TUN: {}", e);
                break;
            }
        }

        // Read from UDP and handle
        match socket.recv_from(&mut udp_buf) {
            Ok((n, src_addr)) => {
                if n < VpnPacket::HEADER_SIZE {
                    warn!("Received short packet from {}", src_addr);
                    continue;
                }

                match VpnPacket::from_bytes(&udp_buf[..n]) {
                    Ok(header) => {
                        info!(
                            "Received packet: type={:?}, client_id={}, seq={}, len={} from {}",
                            header.packet_type, header.client_id, header.sequence,
                            header.length, src_addr
                        );

                        match header.packet_type {
                            PacketType::Handshake => {
                                // Check if already registered
                                let is_new = !clients.values().any(|c| c.addr == src_addr);

                                if is_new {
                                    let client_id = next_client_id;
                                    next_client_id = next_client_id.wrapping_add(1);

                                    let client = Client {
                                        addr: src_addr,
                                        client_id,
                                        sequence: 0,
                                    };
                                    clients.insert(client_id, client);
                                    info!("Registered client {} from {}", client_id, src_addr);

                                    // Send handshake response
                                    let response = VpnPacket::new(
                                        PacketType::Handshake,
                                        client_id,
                                        0,
                                        0,
                                    );
                                    let response_buf = response.to_bytes();
                                    if let Err(e) = socket.send_to(&response_buf, src_addr) {
                                        error!("Failed to send handshake: {}", e);
                                    }
                                } else {
                                    info!("Client {} already registered", src_addr);
                                }
                            }
                            PacketType::Data => {
                                info!(
                                    "Received {} bytes of data from client {}",
                                    header.length, header.client_id
                                );
                                // In a real implementation, write to TUN here
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
                                if let Some(client) = clients.remove(&header.client_id) {
                                    info!(
                                        "Client {} disconnected ({})",
                                        header.client_id, client.addr
                                    );
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
                // No data available, continue
            }
            Err(e) => {
                error!("Error receiving from UDP: {}", e);
                break;
            }
        }

        thread::sleep(Duration::from_millis(10));
    }

    Ok(())
}
