use crate::common::{PacketType, ServerConfig, VpnPacket, TUN_MTU, print_packet_info, tun_io_task};
use anyhow::Result;
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tun2::{create_as_async, Configuration};
use std::net::UdpSocket as StdUdpSocket;

#[derive(Clone)]
struct Client {
    addr: SocketAddr,
    client_id: u32,
    sequence: u32,
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
                            debug!("UDP: Received short packet from {}", src_addr);
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

                                            info!("Client {} connected from {}", next_client_id, src_addr);

                                            let response = VpnPacket::new(
                                                PacketType::Handshake,
                                                next_client_id,
                                                0,
                                                0,
                                            );
                                            let response_buf = response.to_bytes();
                                            if let Err(e) = socket.send_to(&response_buf, src_addr).await {
                                                error!("Failed to send handshake to {}: {}", src_addr, e);
                                            }

                                            next_client_id = next_client_id.wrapping_add(1);
                                        } else {
                                            debug!("Handshake from existing client {}", src_addr);
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
                                            warn!("Invalid payload length from client {}", header.client_id);
                                        }
                                    }
                                    PacketType::KeepAlive => {
                                        debug!("Keepalive received from client {}", header.client_id);
                                        let response = VpnPacket::new(
                                            PacketType::KeepAlive,
                                            header.client_id,
                                            header.sequence,
                                            0,
                                        );
                                        let response_buf = response.to_bytes();
                                        if let Err(e) = socket.send_to(&response_buf, src_addr).await {
                                            warn!("Failed to send keepalive response to {}: {}", src_addr, e);
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
                                debug!("Failed to parse packet from {}: {}", src_addr, e);
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
                        let client_count = clients_map.len();
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
                            debug!("Broadcasted data to {} client(s)", client_count);
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
    info!("Starting server with configuration: {}", config.bind_addr);

    let mut tun_config = Configuration::default();
    tun_config
        .tun_name(&config.tun_name)
        .layer(tun2::Layer::L3)
        .mtu(config.mtu as u16)
        .address(config.tun_addr)
        .netmask(config.tun_netmask)
        .up();

    info!("Creating TUN device: {}", config.tun_name);
    let tun = create_as_async(&tun_config)?;
    info!("TUN device created: {} -> {}", config.tun_name, config.tun_addr);

    let std_socket = StdUdpSocket::bind(&config.bind_addr)?;
    std_socket.set_nonblocking(true)?;

    let socket2_socket = socket2::Socket::from(std_socket);
    socket2_socket.set_recv_buffer_size(config.socket_recv_buffer_size)?;
    socket2_socket.set_send_buffer_size(config.socket_send_buffer_size)?;

    let actual_recv_size = socket2_socket.recv_buffer_size()?;
    let actual_send_size = socket2_socket.send_buffer_size()?;

    let local_addr = socket2_socket.local_addr()?.as_socket().expect("Failed to get socket address");
    info!("Server listening on {} with recv_buffer={}MB (requested: {}MB), send_buffer={}MB (requested: {}MB)",
          local_addr,
          actual_recv_size / 1024 / 1024,
          config.socket_recv_buffer_size / 1024 / 1024,
          actual_send_size / 1024 / 1024,
          config.socket_send_buffer_size / 1024 / 1024);

    let socket = UdpSocket::from_std(socket2_socket.into())?;
    let socket = Arc::new(socket);

    let (tun_to_udp_tx, tun_to_udp_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let (udp_to_tun_tx, udp_to_tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);

    let clients = Arc::new(Mutex::new(HashMap::<u32, Client>::new()));
    let tun_handle = tokio::spawn(
        tun_io_task(
            tun,
            tun_to_udp_tx,
            udp_to_tun_rx
        )
    );
    let udp_handle = tokio::spawn(
        udp_io_task(
            Arc::clone(&socket),
            Arc::clone(&clients),
            tun_to_udp_rx,
            udp_to_tun_tx
        )
    );
    info!("Server ready, waiting for client connections...");

    tokio::signal::ctrl_c().await?;
    info!("Shutting down server...");

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
    recv_buffer: Option<usize>,
    send_buffer: Option<usize>,
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

    if let Some(recv_buffer_mb) = recv_buffer {
        config.socket_recv_buffer_size = recv_buffer_mb * 1024 * 1024;
    }

    if let Some(send_buffer_mb) = send_buffer {
        config.socket_send_buffer_size = send_buffer_mb * 1024 * 1024;
    }

    debug!("Server configuration: {:?}", config);

    run_server(config).await
}
