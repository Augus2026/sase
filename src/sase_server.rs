use crate::common::{PacketType, ServerConfig, VpnPacket, TUN_MTU, print_packet_info, tun_io_task, configure_udp_socket};
use anyhow::Result;
use log::{debug, error, info, warn};
use std::{collections::HashMap, net::Ipv4Addr};
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
    virtual_ip: Ipv4Addr,
}

async fn handle_handshake(
    src_addr: SocketAddr,
    socket: &UdpSocket,
    clients: &Arc<Mutex<HashMap<u32, Client>>>,
    next_client_id: &mut u32,
) {
    let is_new = {
        let clients_map = clients.lock().await;
        !clients_map.values().any(|c| c.addr == src_addr)
    };

    if is_new {
        let virtual_ip = Ipv4Addr::new(10, 0, 0, *next_client_id as u8);

        let client = Client {
            addr: src_addr,
            client_id: *next_client_id,
            sequence: 0,
            virtual_ip,
        };

        {
            let mut clients_map = clients.lock().await;
            clients_map.insert(*next_client_id, client.clone());
        }

        info!("Client {} connected from {}, assigned IP: {}", next_client_id, src_addr, virtual_ip);

        let response = VpnPacket::new(
            PacketType::Handshake,
            *next_client_id,
            0,
            0,
        );
        let response_buf = response.to_bytes();
        if let Err(e) = socket.send_to(&response_buf, src_addr).await {
            error!("Failed to send handshake to {}: {}", src_addr, e);
        }

        *next_client_id = next_client_id.wrapping_add(1);
    } else {
        debug!("Handshake from existing client {}", src_addr);
    }
}

async fn handle_data(
    header: &VpnPacket,
    data: &[u8],
    tun_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
) -> bool {
    let payload_start = VpnPacket::HEADER_SIZE;
    let payload_end = payload_start + header.length as usize;

    if payload_end <= data.len() {
        let payload = data[payload_start..payload_end].to_vec();
        print_packet_info("[udp read]", &payload);
        if let Err(e) = tun_tx.send(payload).await {
            error!("Failed to send to TUN writer: {}", e);
            true
        } else {
            false
        }
    } else {
        warn!("Invalid payload length from client {}", header.client_id);
        false
    }
}

async fn handle_keepalive(
    header: &VpnPacket,
    src_addr: SocketAddr,
    socket: &UdpSocket,
) {
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

async fn handle_disconnect(
    header: &VpnPacket,
    clients: &Arc<Mutex<HashMap<u32, Client>>>,
) {
    let mut clients_map = clients.lock().await;
    if let Some(client) = clients_map.remove(&header.client_id) {
        info!("Client {} disconnected ({})", header.client_id, client.addr);
    }
}

fn get_destination_ip(data: &[u8]) -> Option<Ipv4Addr> {
    if data.len() < 20 {
        return None;
    }

    let version_ihl = data[0];
    let version = version_ihl >> 4;
    if version != 4 {
        return None;
    }

    let dest_ip_bytes: [u8; 4] = data[16..20].try_into().ok()?;
    Some(Ipv4Addr::from(dest_ip_bytes))
}

async fn send_to_client(
    data: &[u8],
    socket: &UdpSocket,
    client: &Client,
) {
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

async fn handle_message(
    header: VpnPacket,
    data: &[u8],
    src_addr: SocketAddr,
    socket: &UdpSocket,
    clients: &Arc<Mutex<HashMap<u32, Client>>>,
    next_client_id: &mut u32,
    tun_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    match header.packet_type {
        PacketType::Handshake => {
            handle_handshake(src_addr, socket, clients, next_client_id).await;
        }
        PacketType::Data => {
            handle_data(&header, data, tun_tx).await;
        }
        PacketType::KeepAlive => {
            handle_keepalive(&header, src_addr, socket).await;
        }
        PacketType::Disconnect => {
            handle_disconnect(&header, clients).await;
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
    let mut next_client_id = 2u32;
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
                                handle_message(
                                    header,
                                    &udp_buf[..n],
                                    src_addr,
                                    &socket,
                                    &clients,
                                    &mut next_client_id,
                                    &tun_tx,
                                ).await;
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
                        if let Some(dest_ip) = get_destination_ip(&data) {
                            let target_client = clients_map.values().find(|c| c.virtual_ip == dest_ip);
                            if let Some(client) = target_client {
                                send_to_client(&data, &socket, client).await;
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
    let mut tun_config = Configuration::default();
    tun_config
        .tun_name(&config.tun_name)
        .layer(tun2::Layer::L3)
        .mtu(config.mtu as u16)
        .address(config.tun_addr)
        .netmask(config.tun_netmask)
        .up();
    let tun = create_as_async(&tun_config)?;

    let std_socket = StdUdpSocket::bind(&config.bind_addr)?;
    std_socket.set_nonblocking(true)?;
    let socket = configure_udp_socket(std_socket, config.socket_recv_buffer_size, config.socket_send_buffer_size)?;
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
    info!("For transparent proxy, run: sudo ./proxy_nat.sh");

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
