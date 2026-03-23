use crate::common::{ServerConfig, tun_io_task};
use crate::transport::{TransportTrait, TcpTransport, UdpTransport, WsTransport};
use crate::codec::{Message, MessageType, Handshake, Data, KeepAlive, TunConfig};
use anyhow::Result;
use log::{error, info, warn};
use std::sync::atomic::{AtomicU32, Ordering};
use std::{collections::HashMap, net::Ipv4Addr};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;
use tun2::{create_as_async, Configuration};
use nanoid;
use lazy_static::lazy_static;

#[derive(Clone)]
struct Client {
    session_id: String,
    addr: SocketAddr,
    virtual_ip: Ipv4Addr,
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    tun_config: TunConfig,
    last_seen: SystemTime,
}

lazy_static! {
    static ref NEXT_CLIENT_ID: AtomicU32 = AtomicU32::new(1);
    static ref SESSIONS: Mutex<HashMap<String, Client>> = Mutex::new(HashMap::new());
}

fn build_session_id() -> String {
    format!("{}", nanoid::nanoid!(21))
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

async fn handle_data(
    data: &[u8],
    transport_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    if let Err(e) = transport_tx.send(data.to_vec()).await {
        warn!("Failed to send to transport writer: {}", e);
    }
}

async fn handle_keepalive(
    src_addr: SocketAddr,
    transport: &mut impl TransportTrait<Error = std::io::Error>,
    timestamp: i64,
) {
    let response = Message::keepalive(KeepAlive { timestamp });
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
    provided_session_id: Option<String>,
) {
    let session_id: String;
    let virtual_ip: Ipv4Addr;
    let tun_config: TunConfig;

    if let Some(provided_id) = provided_session_id {
        // 重连：通过session_id查找原有客户端信息
        let sessions = SESSIONS.lock().await;
        if let Some(existing_client) = sessions.get(&provided_id) {
            session_id = provided_id;
            virtual_ip = existing_client.virtual_ip;
            tun_config = existing_client.tun_config.clone();
            info!("Client reconnecting with session_id: {}, IP: {}", session_id, virtual_ip);
        } else {
            // session_id不存在，创建新会话
            session_id = build_session_id();
            virtual_ip = Ipv4Addr::new(10, 0, 0, client_id as u8);
            tun_config = TunConfig {
                name: format!("tun{}", client_id),
                address: virtual_ip.to_string(),
                netmask: "255.255.255.0".to_string(),
                dns: vec!["114.114.114.114".to_string(), "8.8.8.8".to_string()],
                mtu: 1400,
            };
        }
    } else {
        // 新连接：创建新会话
        session_id = build_session_id();
        virtual_ip = Ipv4Addr::new(10, 0, 0, client_id as u8);
        tun_config = TunConfig {
            name: format!("tun{}", client_id),
            address: virtual_ip.to_string(),
            netmask: "255.255.255.0".to_string(),
            dns: vec!["114.114.114.114".to_string(), "8.8.8.8".to_string()],
            mtu: 1400,
        };
    }

    let message = Message::handshake(Handshake {
        session_id: session_id.clone(),
        tun_config: Some(tun_config.clone()),
    });

    if let Err(e) = transport.send(message, src_addr).await {
        error!("Failed to send handshake to {}: {}", src_addr, e);
        return;
    }

    let client = Client {
        session_id: session_id.clone(),
        addr: src_addr,
        virtual_ip,
        tx: client_tx,
        tun_config: tun_config.clone(),
        last_seen: SystemTime::now(),
    };

    // 更新会话存储
    {
        let mut sessions = SESSIONS.lock().await;
        sessions.insert(session_id.clone(), client.clone());
    }

    // 更新客户端映射
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
    let message = Message::data(Data { payload: data.to_vec() });
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
                        match msg.msg {
                            Some(MessageType::Handshake(handshake)) => {
                                let client_id = NEXT_CLIENT_ID.fetch_add(1, Ordering::SeqCst);
                                let (dummy_tx, _) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
                                let provided_session_id = if handshake.session_id.is_empty() {
                                    None
                                } else {
                                    Some(handshake.session_id.clone())
                                };
                                handle_handshake(src_addr, &mut transport, &clients, dummy_tx, client_id, provided_session_id).await;
                            }
                            Some(MessageType::Data(data)) => {
                                handle_data(&data.payload, &transport_tx).await;
                            }
                            Some(MessageType::Keepalive(keepalive)) => {
                                handle_keepalive(src_addr, &mut transport, keepalive.timestamp).await;
                            }
                            Some(MessageType::Disconnect(disconnect)) => {
                                handle_disconnect(src_addr, &clients).await;
                                info!("Client {} disconnected: {}", src_addr, disconnect.reason);
                            }
                            _ => {
                                info!("Unknown message type from {}", src_addr);
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
                        match msg.msg {
                            Some(MessageType::Handshake(handshake)) => {
                                let provided_session_id = if handshake.session_id.is_empty() {
                                    None
                                } else {
                                    Some(handshake.session_id.clone())
                                };
                                handle_handshake(peer_addr, &mut tcp_transport, &clients, client_tx.clone(), client_id, provided_session_id).await;
                            }
                            Some(MessageType::Data(data)) => {
                                handle_data(&data.payload, &transport_tx).await;
                            }
                            Some(MessageType::Keepalive(keepalive)) => {
                                handle_keepalive(src_addr, &mut tcp_transport, keepalive.timestamp).await;
                            }
                            Some(MessageType::Disconnect(disconnect)) => {
                                handle_disconnect(src_addr, &clients).await;
                                info!("Client {} disconnected: {}", src_addr, disconnect.reason);
                            }
                            _ => {
                                warn!("Unknown message type from {}", src_addr);
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
                        let message = Message::data(Data { payload: data });
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

async fn handle_ws_connection(
    mut ws_transport: WsTransport,
    client_id: u32,
    transport_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    clients: Arc<Mutex<HashMap<u32, Client>>>,
) {
    let peer_addr = ws_transport.peer_addr();
    let (client_tx, mut client_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);

    loop {
        tokio::select! {
            result = ws_transport.next() => {
                match result {
                    Some(Ok((msg, src_addr))) => {
                        match msg.msg {
                            Some(MessageType::Handshake(handshake)) => {
                                let provided_session_id = if handshake.session_id.is_empty() {
                                    None
                                } else {
                                    Some(handshake.session_id.clone())
                                };
                                handle_handshake(peer_addr, &mut ws_transport, &clients, client_tx.clone(), client_id, provided_session_id).await;
                            }
                            Some(MessageType::Data(data)) => {
                                handle_data(&data.payload, &transport_tx).await;
                            }
                            Some(MessageType::Keepalive(keepalive)) => {
                                handle_keepalive(src_addr, &mut ws_transport, keepalive.timestamp).await;
                            }
                            Some(MessageType::Disconnect(disconnect)) => {
                                handle_disconnect(src_addr, &clients).await;
                                info!("Client {} disconnected: {}", src_addr, disconnect.reason);
                            }
                            _ => {
                                warn!("Unknown message type from {}", src_addr);
                            }
                        }
                    }
                    Some(Err(e)) => {
                        error!("Error reading message from {}: {}", peer_addr, e);
                        break;
                    }
                    None => {
                        info!("WS client {} disconnected", peer_addr);
                        break;
                    }
                }
            }

            result = client_rx.recv() => {
                match result {
                    Some(data) => {
                        let message = Message::data(Data { payload: data });
                        if let Err(e) = ws_transport.send(message, peer_addr).await {
                            warn!("Failed to send data to WS client {}: {}", peer_addr, e);
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

async fn run_ws_server(config: ServerConfig, tun: tun2::AsyncDevice) -> Result<()> {
    let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let (transport_tx, transport_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let clients = Arc::new(Mutex::new(HashMap::<u32, Client>::new()));

    let tls_acceptor = if config.transport_type == "wss" {
        Some(WsTransport::create_tls_acceptor(&config.cert_path, &config.key_path).unwrap())
    } else {
        None
    };

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
        let listener = WsTransport::bind(config.bind_addr.to_string().as_str()).await
            .expect("Failed to bind to address");

        loop {
            match WsTransport::accept(&listener, tls_acceptor.as_ref().map(|a| a.clone())).await {
                Ok(ws_transport) => {
                    let client_id = NEXT_CLIENT_ID.fetch_add(1, Ordering::SeqCst);

                    let tx = transport_tx.clone();
                    let clients = Arc::clone(&clients);

                    tokio::spawn(async move {
                        handle_ws_connection(
                            ws_transport,
                            client_id,
                            tx,
                            clients,
                        ).await
                    });
                }
                Err(e) => {
                    error!("Failed to accept WS connection: {}", e);
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

pub async fn run_server(config: ServerConfig) -> Result<()> {
    // 启动会话清理任务
    tokio::spawn(cleanup_expired_sessions());

    let mut tun_config = Configuration::default();
    tun_config
        .tun_name(&config.tun_name)
        .layer(tun2::Layer::L3)
        .mtu(config.mtu as u16)
        .address(config.tun_addr)
        .netmask(config.tun_netmask)
        .up();
    let tun = create_as_async(&tun_config)?;

    match config.transport_type.to_lowercase().as_str() {
        "tcp" => {
            info!("Using TCP transport");
            run_tcp_server(config, tun).await
        }
        "udp" => {
            info!("Using UDP transport");
            run_udp_server(config, tun).await
        }
        "ws" => {
            info!("Using WebSocket transport");
            run_ws_server(config, tun).await
        }
        "wss" => {
            info!("Using WebSocket(Secure) transport");
            run_ws_server(config, tun).await
        }
        _ => {
            error!("Unknown transport type: {}", config.transport_type);
            Err(anyhow::anyhow!("Unknown transport type: {}", config.transport_type))
        }
    }
}

pub async fn run_server_with_args(
    transport_type: Option<String>,
    bind_addr: Option<String>,
    tun: Option<String>,
    address: Option<String>,
    netmask: Option<String>,
    mtu: Option<usize>,
    cert_path: Option<String>,
    key_path: Option<String>,
) -> Result<()> {
    let mut config = ServerConfig::default();

    if let Some(transport_type) = transport_type {
        config.transport_type = transport_type;
    }

    if let Some(bind_addr) = bind_addr {
        config.bind_addr = bind_addr.parse()?;
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

    if let Some(cert_path) = cert_path {
        config.cert_path = cert_path;
    }

    if let Some(key_path) = key_path {
        config.key_path = key_path;
    }

    info!("Server configuration: {:?}", config);

    run_server(config).await
}

async fn cleanup_expired_sessions() {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;

        let mut sessions = SESSIONS.lock().await;
        let now = SystemTime::now();
        let mut removed_count = 0;

        sessions.retain(|session_id, client| {
            let elapsed = now.duration_since(client.last_seen).unwrap_or(Duration::MAX);
            let should_keep = elapsed < Duration::from_secs(300); // 5分钟未活动则清理

            if !should_keep {
                info!("Cleaning up expired session: {}, last seen: {:?}", session_id, client.last_seen);
                removed_count += 1;
            }

            should_keep
        });

        if removed_count > 0 {
            info!("Cleaned up {} expired sessions", removed_count);
        }
    }
}
