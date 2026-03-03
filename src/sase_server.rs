use crate::common::{PacketType, ServerConfig, VpnPacket, TUN_MTU, print_packet_info, tun_io_task};
use crate::transport::Transport;
use crate::tcp_transport::TcpTransport;
use crate::udp_transport::UdpTransport;
use anyhow::Result;
use log::{error, info, warn};
use std::{collections::HashMap, net::Ipv4Addr};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tun2::{create_as_async, Configuration};

#[derive(Clone)]
struct Client {
    addr: SocketAddr,
    client_id: u32,
    sequence: u32,
    virtual_ip: Ipv4Addr,
    transport: Arc<dyn Transport>,
}

async fn handle_handshake(
    src_addr: SocketAddr,
    transport: Arc<dyn Transport>,
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
            transport: Arc::clone(&transport),
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
        if let Err(e) = transport.send_to(&response_buf, src_addr).await {
            error!("Failed to send handshake to {}: {}", src_addr, e);
        }

        *next_client_id = next_client_id.wrapping_add(1);
    } else {
        info!("Handshake from existing client {}", src_addr);
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
        print_packet_info("[transport read]", &payload);
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
    transport: &dyn Transport,
) {
    info!("Keepalive received from client {}", header.client_id);
    let response = VpnPacket::new(
        PacketType::KeepAlive,
        header.client_id,
        header.sequence,
        0,
    );
    let response_buf = response.to_bytes();
    if let Err(e) = transport.send_to(&response_buf, src_addr).await {
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
    transport: &dyn Transport,
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

    print_packet_info("[transport write]", &send_buf);
    if let Err(e) = transport.send_to(&send_buf, client.addr).await {
        warn!("Failed to send to {}: {}", client.addr, e);
    }
}

async fn handle_message(
    header: VpnPacket,
    data: &[u8],
    src_addr: SocketAddr,
    transport: Arc<dyn Transport>,
    clients: &Arc<Mutex<HashMap<u32, Client>>>,
    next_client_id: &mut u32,
    tun_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    match header.packet_type {
        PacketType::Handshake => {
            handle_handshake(src_addr, Arc::clone(&transport), clients, next_client_id).await;
        }
        PacketType::Data => {
            handle_data(&header, data, tun_tx).await;
        }
        PacketType::KeepAlive => {
            handle_keepalive(&header, src_addr, transport.as_ref()).await;
        }
        PacketType::Disconnect => {
            handle_disconnect(&header, clients).await;
        }
    }
}

async fn transport_io_task(
    transport: Arc<dyn Transport>,
    clients: Arc<Mutex<HashMap<u32, Client>>>,
    mut tun_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    tun_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    let mut transport_buf = vec![0u8; VpnPacket::HEADER_SIZE + TUN_MTU];
    let mut next_client_id = 2u32;
    info!("Transport I/O task started");

    loop {
        tokio::select! {
            result = transport.recv_from(&mut transport_buf) => {
                match result {
                    Ok((n, src_addr)) => {
                        if n < VpnPacket::HEADER_SIZE {
                            info!("Transport: Received short packet from {}", src_addr);
                            continue;
                        }

                        match VpnPacket::from_bytes(&transport_buf[..n]) {
                            Ok(header) => {
                                handle_message(
                                    header,
                                    &transport_buf[..n],
                                    src_addr,
                                    Arc::clone(&transport),
                                    &clients,
                                    &mut next_client_id,
                                    &tun_tx,
                                ).await;
                            }
                            Err(e) => {
                                info!("Failed to parse packet from {}: {}", src_addr, e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Transport: Error receiving: {}", e);
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
                                send_to_client(&data, transport.as_ref(), client).await;
                            }
                        }
                    }
                    None => {
                        error!("Transport: Channel disconnected");
                        break;
                    }
                }
            }
        }
    }
}

pub async fn run_server(config: ServerConfig, transport_type: String) -> Result<()> {
    let mut tun_config = Configuration::default();
    tun_config
        .tun_name(&config.tun_name)
        .layer(tun2::Layer::L3)
        .mtu(config.mtu as u16)
        .address(config.tun_addr)
        .netmask(config.tun_netmask)
        .up();
    let tun = create_as_async(&tun_config)?;

    match transport_type.to_lowercase().as_str() {
        "tcp" => {
            info!("Using TCP transport");
            run_tcp_server(config, tun).await
        }
        "udp" => {
            info!("Using UDP transport");
            run_udp_server(config, tun).await
        }
        _ => {
            error!("Unknown transport type: {}", transport_type);
            Err(anyhow::anyhow!("Unknown transport type: {}", transport_type))
        }
    }
}

async fn run_udp_server(config: ServerConfig, tun: tun2::AsyncDevice) -> Result<()> {
    let udp_transport = UdpTransport::new(config.bind_addr)?;
    let transport: Arc<dyn Transport> = Arc::new(udp_transport);

    let (tun_to_transport_tx, tun_to_transport_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let (transport_to_tun_tx, transport_to_tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let clients = Arc::new(Mutex::new(HashMap::<u32, Client>::new()));
    let tun_handle = tokio::spawn(
        tun_io_task(
            tun,
            tun_to_transport_tx,
            transport_to_tun_rx
        )
    );
    let transport_handle = tokio::spawn(
        transport_io_task(
            Arc::clone(&transport),
            Arc::clone(&clients),
            tun_to_transport_rx,
            transport_to_tun_tx
        )
    );

    tokio::signal::ctrl_c().await?;
    info!("Shutting down server...");

    tun_handle.abort();
    transport_handle.abort();

    Ok(())
}

async fn tcp_send_io_task(
    clients: Arc<Mutex<HashMap<u32, Client>>>,
    mut tun_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) {
    loop {
        match tun_rx.recv().await {
            Some(data) => {
                let clients_map = clients.lock().await;
                if let Some(dest_ip) = get_destination_ip(&data) {
                    let target_client = clients_map.values().find(|c| c.virtual_ip == dest_ip);
                    if let Some(client) = target_client {
                        let transport = client.transport.clone();
                        send_to_client(&data, transport.as_ref(), client).await;
                    }
                }
            }
            None => {
                error!("Transport: Channel disconnected");
                break;
            }
        }
    }
}

async fn tcp_recv_io_task(
    transport: Arc<dyn Transport>,
    clients: Arc<Mutex<HashMap<u32, Client>>>,
    tun_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    let mut transport_buf = vec![0u8; VpnPacket::HEADER_SIZE + TUN_MTU];
    let mut next_client_id = 2u32;
    info!("Transport I/O task started");

    loop {
        match transport.recv_from(&mut transport_buf).await {
            Ok((n, src_addr)) => {
                if n < VpnPacket::HEADER_SIZE {
                    info!("Transport: Received short packet from {}", src_addr);
                    continue;
                }

                match VpnPacket::from_bytes(&transport_buf[..n]) {
                    Ok(header) => {
                        handle_message(
                            header,
                            &transport_buf[..n],
                            src_addr,
                            Arc::clone(&transport),
                            &clients,
                            &mut next_client_id,
                            &tun_tx,
                        )
                        .await;
                    }
                    Err(e) => {
                        info!("Failed to parse packet from {}: {}", src_addr, e);
                    }
                }
            }
            Err(e) => {
                error!("Transport: Error receiving: {}", e);
                break;
            }
        }
    }
}

async fn run_tcp_server(config: ServerConfig, tun: tun2::AsyncDevice) -> Result<()> {
    let (tun_to_transport_tx, tun_to_transport_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let (transport_to_tun_tx, transport_to_tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let clients = Arc::new(Mutex::new(HashMap::<u32, Client>::new()));

    let tun_handle = tokio::spawn(
        tun_io_task(
            tun,
            tun_to_transport_tx,
            transport_to_tun_rx
        )
    );

    let tcp_send_handle = tokio::spawn(
        tcp_send_io_task(
            Arc::clone(&clients),
            tun_to_transport_rx
        )
    );

    // Start TCP accept loop in a separate task
    let clients_clone = Arc::clone(&clients);
    let tun_tx_clone = transport_to_tun_tx.clone();
    let accept_task = tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(&config.bind_addr).await {
            Ok(l) => {
                info!("TCP server listening on {}", config.bind_addr);
                l
            }
            Err(e) => {
                error!("Failed to bind TCP listener: {}", e);
                return;
            }
        };

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    // Disable Nagle's algorithm to reduce latency for small packets
                    if let Err(e) = stream.set_nodelay(true) {
                        error!("Failed to set TCP_NODELAY: {}", e);
                        continue;
                    }
                    info!("TCP connection accepted from {}", addr);

                    match TcpTransport::from_stream(stream, addr) {
                        Ok(tcp_transport) => {
                            let transport: Arc<dyn Transport> = Arc::new(tcp_transport);
                            let clients = Arc::clone(&clients_clone);
                            let tun_tx = tun_tx_clone.clone();
                            tokio::spawn(async move {
                                tcp_recv_io_task(transport, clients, tun_tx).await;
                            });
                        }
                        Err(e) => {
                            error!("Failed to create TCP transport: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to accept TCP connection: {}", e);
                    break;
                }
            }
        }
    });

    // Wait for Ctrl+C to shutdown
    if let Err(e) = tokio::signal::ctrl_c().await {
        error!("Failed to wait for Ctrl+C: {}", e);
    }
    info!("Shutting down server...");

    tun_handle.abort();
    tcp_send_handle.abort();
    accept_task.abort();

    Ok(())
}

pub async fn run_server_with_args(
    bind: Option<String>,
    tun: Option<String>,
    address: Option<String>,
    netmask: Option<String>,
    mtu: Option<usize>,
    transport: Option<String>,
) -> Result<()> {
    let mut config = ServerConfig::default();
    let transport_type = transport.unwrap_or_else(|| "udp".to_string());

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

    info!("Server configuration: {:?}", config);
    info!("Transport protocol: {}", transport_type);

    run_server(config, transport_type).await
}
