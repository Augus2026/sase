use crate::common::{ServerConfig, print_packet_info, tun_io_task};
use crate::transport::{TransportTrait, TcpTransport, UdpTransport};
use crate::codec::{Message, MessageType};
use crate::tun_config::{TunConfig, build_tun_config, serialize_tun_config};
use anyhow::Result;
use log::{error, info, warn};
use std::sync::atomic::{AtomicU32, Ordering};
use std::{collections::HashMap, net::Ipv4Addr};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tun2::{create_as_async, Configuration};

#[derive(Clone)]
struct Client {
    addr: SocketAddr,
    virtual_ip: Ipv4Addr,
    tun_config: TunConfig,
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
}

static NEXT_CLIENT_ID: AtomicU32 = AtomicU32::new(1);

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

async fn handle_data(
    data: &[u8],
    transport_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    print_packet_info("[transport read]", &data);
    if let Err(e) = transport_tx.send(data.to_vec()).await {
        warn!("Failed to send to transport writer: {}", e);
    }
}

async fn handle_keepalive(
    src_addr: SocketAddr,
    transport: &mut impl TransportTrait<Error = std::io::Error>,
    msg_data: Vec<u8>,
) {
    let response = Message::keepalive(msg_data);
    if let Err(e) = transport.send(response, src_addr).await {
        warn!("Failed to send keepalive response to {}: {}", src_addr, e);
    }
}

async fn handle_handshake(
    src_addr: SocketAddr,
    transport: &mut impl TransportTrait<Error = std::io::Error>,
    clients: &Arc<Mutex<HashMap<u32, Client>>>,
    client_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    client_id: u32,
) {
    let virtual_ip = Ipv4Addr::new(10, 0, 0, client_id as u8);
    let tun_config = build_tun_config(client_id, &virtual_ip.to_string());
    let mut response_data = client_id.to_be_bytes().to_vec();
    response_data.extend_from_slice(&serialize_tun_config(&tun_config));
    let message = Message::handshake(response_data);

    if let Err(e) = transport.send(message, src_addr).await {
        error!("Failed to send handshake to {}: {}", src_addr, e);
        return;
    }
    
    let client = Client {
        addr: src_addr,
        virtual_ip,
        tun_config,
        tx: client_tx,
    };

    {
        let mut clients_map = clients.lock().await;
        clients_map.insert(client_id, client);
    }

    info!("Client {} connected from {}, assigned IP: {}", client_id, src_addr, virtual_ip);
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

async fn handle_tun_packet(
    tun_rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
    clients: &Arc<Mutex<HashMap<u32, Client>>>,
) {
    while let Some(data) = tun_rx.recv().await {
        let clients_map = clients.lock().await;
        if let Some(dest_ip) = get_destination_ip(&data) {
            let target_client = clients_map.values().find(|c| c.virtual_ip == dest_ip);
            if let Some(client) = target_client {
                print_packet_info("[transport write]", &data);
                if let Err(e) = client.tx.send(data).await {
                    warn!("Failed to send to client {}: {}", client.addr, e);
                }
            }
        }
    }
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
    info!("UDP transport I/O task started");

    loop {
        tokio::select! {
            result = transport.next() => {
                match result {
                    Some(Ok((msg, src_addr))) => {
                        match MessageType::try_from(msg.message_type) {
                            Ok(MessageType::Handshake) => {
                                let client_id = NEXT_CLIENT_ID.fetch_add(1, Ordering::SeqCst);
                                let (dummy_tx, _) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
                                handle_handshake(src_addr, &mut transport, &clients, dummy_tx, client_id).await;
                            }
                            Ok(MessageType::Data) => {
                                handle_data(&msg.data, &transport_tx).await;
                            }
                            Ok(MessageType::KeepAlive) => {
                                handle_keepalive(src_addr, &mut transport, msg.data).await;
                            }
                            Ok(MessageType::Disconnect) => {
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

async fn run_udp_server(config: ServerConfig, tun: tun2::AsyncDevice) -> Result<()> {
    let (tun_tx, tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let (transport_tx, transport_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let clients = Arc::new(Mutex::new(HashMap::<u32, Client>::new()));

    let transport = UdpTransport::bind(config.bind_addr.to_string().as_str()).await?;

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

    tokio::select! {
        _ = tun_handle => {},
        _ = transport_handle => {},
    }
    Ok(())
}

async fn handle_tcp_connection(
    mut tcp_transport: TcpTransport,
    client_id: u32,
    transport_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    clients: Arc<Mutex<HashMap<u32, Client>>>,
) {
    let peer_addr = tcp_transport.peer_addr();
    let (client_tx, mut client_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);

    loop {
        tokio::select! {
            result = tcp_transport.next() => {
                match result {
                    Some(Ok((msg, src_addr))) => {
                        match MessageType::try_from(msg.message_type) {
                            Ok(MessageType::Handshake) => {
                                handle_handshake(peer_addr, &mut tcp_transport, &clients, client_tx.clone(), client_id).await;
                            }
                            Ok(MessageType::Data) => {
                                handle_data(&msg.data, &transport_tx).await;
                            }
                            Ok(MessageType::KeepAlive) => {
                                handle_keepalive(src_addr, &mut tcp_transport, msg.data).await;
                            }
                            Ok(MessageType::Disconnect) => {
                                handle_disconnect(src_addr, &clients).await;
                            }
                            _ => {
                                warn!("Unknown message type: from {}: {}", src_addr, msg.message_type);
                            }
                        }
                    }
                    Some(Err(e)) => {
                        error!("Error reading message from {}: {}", peer_addr, e);
                        break;
                    }
                    None => {
                        info!("Client {} disconnected", peer_addr);
                        break;
                    }
                }
            }

            result = client_rx.recv() => {
                match result {
                    Some(data) => {
                        print_packet_info("[transport write]", &data);
                        let message = Message::data(data);
                        if let Err(e) = tcp_transport.send(message, peer_addr).await {
                            warn!("Failed to send data to {}: {}", peer_addr, e);
                            break;
                        }
                    }
                    None => {
                        break;
                    }
                }
            }
        }
    }

    let mut clients_map = clients.lock().await;
    clients_map.remove(&client_id);
}

async fn run_tcp_server(config: ServerConfig, tun: tun2::AsyncDevice) -> Result<()> {
    let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let (transport_tx, transport_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let clients = Arc::new(Mutex::new(HashMap::<u32, Client>::new()));

    let tun_handle = tokio::spawn(
        tun_io_task(
            tun,
            tun_tx,
            transport_rx
        )
    );

    let clients_clone = Arc::clone(&clients);
    tokio::spawn(async move {
        handle_tun_packet(&mut tun_rx, &clients_clone).await;
    });

    let accept_task = tokio::spawn(async move {
        let listener = TcpTransport::bind(config.bind_addr.to_string().as_str()).await
            .expect("Failed to bind to address");
        info!("TCP server listening on {}", config.bind_addr);

        loop {
            match TcpTransport::accept(&listener).await {
                Ok(tcp_transport) => {
                    let client_id = NEXT_CLIENT_ID.fetch_add(1, Ordering::SeqCst);

                    let tx = transport_tx.clone();
                    let clients = Arc::clone(&clients);

                    tokio::spawn(async move {
                        handle_tcp_connection(
                            tcp_transport,
                            client_id,
                            tx,
                            clients,
                        ).await
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    });

    tokio::select! {
        _ = tun_handle => {},
        _ = accept_task => {},
    }
    Ok(())
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
