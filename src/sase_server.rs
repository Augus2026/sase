use crate::common::{ServerConfig, print_packet_info, tun_io_task};
use crate::transport::{TransportTrait, TcpTransport, UdpTransport};
use crate::codec::{Message, MessageType};
use anyhow::Result;
use log::{debug, error, info, warn};
use std::{collections::HashMap, net::Ipv4Addr};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tun2::{create_as_async, Configuration};

#[derive(Clone)]
struct Client {
    addr: SocketAddr,
    virtual_ip: Ipv4Addr,
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
}

async fn handle_data(
    data: &[u8],
    transport_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
) -> bool {
    print_packet_info("[transport read]", &data);
    if let Err(e) = transport_tx.send(data.to_vec()).await {
        error!("Failed to send to transport writer: {}", e);
        true
    } else {
        false
    }
}

async fn handle_keepalive(
    src_addr: SocketAddr,
    transport: &mut impl TransportTrait<Error = std::io::Error>,
    msg_data: Vec<u8>,
) {
    debug!("Keepalive received from {}", src_addr);
    // Echo back the timestamp data for latency measurement
    let response = Message::keepalive(msg_data);
    if let Err(e) = transport.send(response, src_addr).await {
        warn!("Failed to send keepalive response to {}: {}", src_addr, e);
    }
}

async fn handle_disconnect(
    addr: SocketAddr,
    clients: &Arc<Mutex<HashMap<u32, Client>>>,
) {
    let mut clients_map = clients.lock().await;
    if let Some((client_id, client)) = clients_map.iter().find(|(_, c)| c.addr == addr).map(|(k, v)| (*k, v.clone())) {
        clients_map.remove(&client_id);
        info!("Client {} disconnected ({})", client_id, client.addr);
    }
}

async fn handle_handshake(
    msg: Message,
    transport: &mut TcpTransport,
    peer_addr: SocketAddr,
    client_id: u32,
    clients: &Arc<Mutex<HashMap<u32, Client>>>,
    client_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
) -> Result<bool> {
    if msg.message_type != MessageType::Handshake as u8 {
        warn!("Expected handshake message, got type: {}", msg.message_type);
        return Ok(false);
    }

    let virtual_ip = Ipv4Addr::new(10, 0, 0, client_id as u8);
    let response_data = client_id.to_be_bytes().to_vec();
    let message = Message::handshake(response_data);

    if let Err(e) = transport.send(message, peer_addr).await {
        error!("Failed to send handshake response: {}", e);
        return Ok(false);
    }

    let client = Client {
        addr: peer_addr,
        virtual_ip,
        tx: client_tx,
    };

    {
        let mut clients_map = clients.lock().await;
        clients_map.insert(client_id, client);
    }

    info!("Client {} connected from {}, assigned IP: {}", client_id, peer_addr, virtual_ip);
    Ok(true)
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
    transport: &mut impl TransportTrait<Error = std::io::Error>,
    client: &Client,
) {
    print_packet_info("[transport write]", &data);
    let message = Message::data(data.to_vec());

    if let Err(e) = transport.send(message, client.addr).await {
        warn!("Failed to send to {}: {}", client.addr, e);
    }
}

async fn udp_transport_io_task(
    mut transport: UdpTransport,
    clients: Arc<Mutex<HashMap<u32, Client>>>,
    mut tun_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    transport_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    let mut next_client_id = 2u32;
    info!("UDP transport I/O task started");

    loop {
        tokio::select! {
            result = transport.next() => {
                match result {
                    Some(Ok((msg, src_addr))) => {
                        match msg.message_type {
                            t if t == MessageType::Handshake as u8 => {
                                let virtual_ip = Ipv4Addr::new(10, 0, 0, next_client_id as u8);
                                let response_data = next_client_id.to_be_bytes().to_vec();
                                let message = Message::handshake(response_data);

                                if let Err(e) = transport.send(message, src_addr).await {
                                    error!("Failed to send handshake to {}: {}", src_addr, e);
                                } else {
                                    let (dummy_tx, _) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
                                    let client = Client {
                                        addr: src_addr,
                                        virtual_ip,
                                        tx: dummy_tx,
                                    };
                                    {
                                        let mut clients_map = clients.lock().await;
                                        clients_map.insert(next_client_id, client);
                                    }
                                    info!("Client {} connected from {}, assigned IP: {}", next_client_id, src_addr, virtual_ip);
                                    next_client_id = next_client_id.wrapping_add(1);
                                }
                            }
                            t if t == MessageType::Data as u8 => {
                                handle_data(&msg.data, &transport_tx).await;
                            }
                            t if t == MessageType::KeepAlive as u8 => {
                                handle_keepalive(src_addr, &mut transport, msg.data).await;
                            }
                            t if t == MessageType::Disconnect as u8 => {
                                handle_disconnect(src_addr, &clients).await;
                            }
                            _ => {
                                info!("Unknown message type from {}: {}", src_addr, msg.message_type);
                            }
                        }
                    }
                    Some(Err(e)) => {
                        error!("Error reading message: {}", e);
                        break;
                    }
                    None => {
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
                                send_to_client(&data, &mut transport, client).await;
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
    let transport = UdpTransport::bind(config.bind_addr.to_string().as_str()).await?;

    let (tun_tx, tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let (transport_tx, transport_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let clients = Arc::new(Mutex::new(HashMap::<u32, Client>::new()));

    let tun_handle = tokio::spawn(
        tun_io_task(
            tun,
            tun_tx,
            transport_rx
        )
    );
    let transport_handle = tokio::spawn(
        udp_transport_io_task(
            transport,
            Arc::clone(&clients),
            tun_rx,
            transport_tx
        )
    );

    tokio::signal::ctrl_c().await?;
    info!("Shutting down server...");

    tun_handle.abort();
    transport_handle.abort();

    Ok(())
}

async fn handle_tcp_client_connection(
    tcp_transport: TcpTransport,
    client_id: u32,
    transport_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    clients: Arc<Mutex<HashMap<u32, Client>>>,
) {
    let _peer_addr = tcp_transport.peer_addr();
    let (client_tx, mut client_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let tcp_transport_shared = Arc::new(Mutex::new(tcp_transport));
    let tcp_transport_for_send = Arc::clone(&tcp_transport_shared);
    let mut transport_guard = tcp_transport_shared.lock().await;
    let peer_addr = transport_guard.peer_addr();
    let handshake_result = transport_guard.next().await;
    drop(transport_guard);

    match handshake_result {
        Some(Ok((msg, _))) => {
            let handshake_success = handle_handshake(
                msg,
                &mut *tcp_transport_shared.lock().await,
                peer_addr,
                client_id,
                &clients,
                client_tx,
            ).await;

            if !handshake_success.unwrap_or(false) {
                return;
            }

            let peer_addr_for_send = peer_addr;
            tokio::spawn(async move {
                while let Some(data) = client_rx.recv().await {
                    print_packet_info("[transport write]", &data);
                    let message = Message::data(data);
                    let mut transport_guard = tcp_transport_for_send.lock().await;
                    if let Err(e) = transport_guard.send(message, peer_addr_for_send).await {
                        warn!("Failed to send to {}: {}", peer_addr_for_send, e);
                        drop(transport_guard);
                        break;
                    }
                    drop(transport_guard);
                }
            });

            loop {
                let mut transport_guard = tcp_transport_shared.lock().await;
                match transport_guard.next().await {
                    Some(Ok((msg, _addr))) => {
                        drop(transport_guard);
                        match msg.message_type {
                            t if t == MessageType::Data as u8 => {
                                print_packet_info("[transport read]", &msg.data);
                                if let Err(e) = transport_tx.send(msg.data).await {
                                    error!("Failed to send to TUN: {}", e);
                                    break;
                                }
                            }
                            t if t == MessageType::KeepAlive as u8 => {
                                // Echo back the timestamp data for latency measurement
                                let response = Message::keepalive(msg.data);
                                let mut transport_guard = tcp_transport_shared.lock().await;
                                if let Err(e) = transport_guard.send(response, peer_addr).await {
                                    warn!("Failed to send keepalive response: {}", e);
                                }
                            }
                            t if t == MessageType::Disconnect as u8 => {
                                let mut clients_map = clients.lock().await;
                                clients_map.remove(&client_id);
                                info!("Client {} disconnected", client_id);
                                break;
                            }
                            _ => {}
                        }
                    }
                    Some(Err(e)) => {
                        error!("Error reading message: {}", e);
                        break;
                    }
                    None => {
                        break;
                    }
                }
            }
        }
        Some(Err(e)) => {
            error!("Error reading handshake: {}", e);
        }
        None => {
            info!("Client disconnected before handshake");
        }
    }
}

async fn run_tcp_server(config: ServerConfig, tun: tun2::AsyncDevice) -> Result<()> {
    let (tun_tx, tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let (transport_tx, transport_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let clients = Arc::new(Mutex::new(HashMap::<u32, Client>::new()));

    let tun_handle = tokio::spawn(
        tun_io_task(
            tun,
            tun_tx,
            transport_rx
        )
    );

    let listener = TcpTransport::bind(config.bind_addr.to_string().as_str()).await?;
    info!("TCP server listening on {}", config.bind_addr);

    let clients_clone = Arc::clone(&clients);
    let transport_tx_for_accept = transport_tx.clone();
    let accept_task = tokio::spawn(async move {
        let mut next_client_id = 2u32;
        loop {
            match TcpTransport::accept(&listener).await {
                Ok(tcp_transport) => {
                    let peer_addr = tcp_transport.peer_addr();
                    info!("New TCP connection from {}", peer_addr);

                    let client_id = next_client_id;
                    next_client_id = next_client_id.wrapping_add(1);

                    let transport_tx_clone = transport_tx_for_accept.clone();
                    let clients_clone_clone = Arc::clone(&clients_clone);

                    // Spawn connection handler
                    tokio::spawn(async move {
                        handle_tcp_client_connection(
                            tcp_transport,
                            client_id,
                            transport_tx_clone,
                            clients_clone_clone,
                        ).await
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    });

    // Handle sending data from TUN to TCP clients
    drop(transport_tx);
    let clients_for_tun = Arc::clone(&clients);
    tokio::spawn(async move {
        let mut tun_rx = tun_rx;
        while let Some(data) = tun_rx.recv().await {
            let clients_map = clients_for_tun.lock().await;
            if let Some(dest_ip) = get_destination_ip(&data) {
                let target_client = clients_map.values().find(|c| c.virtual_ip == dest_ip);
                if let Some(client) = target_client {
                    if let Err(e) = client.tx.send(data).await {
                        warn!("Failed to send to client {}: {}", client.addr, e);
                    }
                }
            }
        }
    });

    tokio::signal::ctrl_c().await?;
    info!("Shutting down server...");

    tun_handle.abort();
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
