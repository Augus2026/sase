use crate::common::{ClientConfig, PacketType, VpnPacket, TUN_MTU};
use anyhow::Result;
use log::{error, info, warn};
use std::io::Read;
use std::net::UdpSocket;
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

    // #[cfg(target_os = "linux")]
    // {
    //     tun_config.platform_specific(|config| {
    //         // Linux-specific configuration
    //     });
    // }

    let mut tun = create(&tun_config)?;
    info!("TUN device created: {} -> {}", config.tun_name, config.tun_addr);

    // Create UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_nonblocking(true)?;
    info!("Client bound to {}", socket.local_addr()?);

    // Client state
    let mut client_id: u32 = 0;
    let mut sequence: u32 = 0;
    let mut connected = false;

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
                if addr.to_string() == config.server_addr.to_string() {
                    match VpnPacket::from_bytes(&resp_buf[..n]) {
                        Ok(header) if header.packet_type == PacketType::Handshake => {
                            info!("Connected! Client ID: {}", header.client_id);
                            client_id = header.client_id;
                            connected = true;
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

    let mut tun_buf = vec![0u8; TUN_MTU];
    let mut udp_buf = vec![0u8; VpnPacket::HEADER_SIZE + TUN_MTU];
    let mut last_keepalive = std::time::Instant::now();

    loop {
        // Read from TUN and forward to server
        match tun.read(&mut tun_buf) {
            Ok(n) => {
                if !connected {
                    continue;
                }

                info!("Client: Read {} bytes from TUN", n);

                let packet = VpnPacket::new(PacketType::Data, client_id, sequence, n as u16);

                let mut send_buf = vec![0u8; VpnPacket::HEADER_SIZE + n];
                send_buf[..VpnPacket::HEADER_SIZE].copy_from_slice(&packet.to_bytes());
                send_buf[VpnPacket::HEADER_SIZE..].copy_from_slice(&tun_buf[..n]);

                if let Err(e) = socket.send_to(&send_buf, config.server_addr) {
                    warn!("Failed to send to server: {}", e);
                } else {
                    sequence += 1;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No data available
            }
            Err(e) => {
                error!("Error reading from TUN: {}", e);
                break;
            }
        }

        // Read from UDP and handle
        match socket.recv_from(&mut udp_buf) {
            Ok((n, src_addr)) => {
                if src_addr != config.server_addr {
                    warn!("Received packet from unexpected address: {}", src_addr);
                    continue;
                }

                if n < VpnPacket::HEADER_SIZE {
                    warn!("Received short packet from {}", src_addr);
                    continue;
                }

                match VpnPacket::from_bytes(&udp_buf[..n]) {
                    Ok(header) => {
                        if header.client_id != client_id {
                            warn!("Packet for different client ID");
                            continue;
                        }

                        info!(
                            "Client received: type={:?}, seq={}, len={}",
                            header.packet_type, header.sequence, header.length
                        );

                        match header.packet_type {
                            PacketType::Data => {
                                info!("Received {} bytes of data from server", header.length);
                                // In a real implementation, write to TUN here
                            }
                            PacketType::KeepAlive => {
                                info!("Received keepalive from server");
                            }
                            PacketType::Disconnect => {
                                error!("Server disconnected");
                                break;
                            }
                            _ => {
                                info!("Received packet type: {:?}", header.packet_type);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse packet: {}", e);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No data available
            }
            Err(e) => {
                error!("Error receiving from UDP: {}", e);
                break;
            }
        }

        // Send keepalive every 10 seconds
        if last_keepalive.elapsed() >= Duration::from_secs(10) {
            let packet = VpnPacket::new(PacketType::KeepAlive, client_id, sequence, 0);
            let buf = packet.to_bytes();
            if let Err(e) = socket.send_to(&buf, config.server_addr) {
                warn!("Failed to send keepalive: {}", e);
            } else {
                info!("Sent keepalive to server");
            }
            last_keepalive = std::time::Instant::now();
        }

        thread::sleep(Duration::from_millis(10));
    }

    Ok(())
}
