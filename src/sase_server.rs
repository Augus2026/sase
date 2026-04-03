use crate::codec::{Data, Handshake, KeepAlive, Message, MessageType, TunConfig};
use crate::common::{load_routing_engine, tun_io_task, ServerConfig};
use crate::transport::{TcpTransport, TransportTrait, UdpTransport, WsTransport};
use anyhow::Result;
use lazy_static::lazy_static;
use log::{error, info, warn};
use nanoid;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime};
use std::{collections::HashMap, net::Ipv4Addr};
use tokio::sync::Mutex;
use tun2::{create_as_async, Configuration};

#[derive(Debug, Clone)]
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

fn validate_token(token: &str, server_token: &str) -> bool {
    if server_token.is_empty() {
        return true;
    }
    token == server_token
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

async fn handle_data(data: &[u8], transport_tx: &tokio::sync::mpsc::Sender<Vec<u8>>) {
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
    client_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    provided_session_id: Option<String>,
    provided_token: Option<String>,
) {
    let server_token = ServerConfig::load().unwrap().token.clone();
    let session_id: String;
    let virtual_ip: Ipv4Addr;
    let tun_config: TunConfig;

    if let Some(handshake_token) = provided_token {
        if !validate_token(&handshake_token, server_token.as_str()) {
            warn!(
                "Invalid token provided by {}: {}",
                src_addr, handshake_token
            );

            let message = Message::handshake(Handshake {
                token: String::new(),
                session_id: String::new(),
                tun_config: None,
            });

            if let Err(e) = transport.send(message, src_addr).await {
                error!("Failed to send handshake to {}: {}", src_addr, e);
                return;
            }

            return;
        } else {
            info!("Valid token provided by {}: {}", src_addr, handshake_token);
        }
    }

    if let Some(provided_id) = provided_session_id {
        let sessions_map = SESSIONS.lock().await;
        if let Some(existing_client) = sessions_map.get(&provided_id) {
            session_id = provided_id;
            virtual_ip = existing_client.virtual_ip;
            tun_config = existing_client.tun_config.clone();
            info!(
                "Client reconnecting with session_id: {}, IP: {}",
                session_id, virtual_ip
            );
        } else {
            session_id = build_session_id();
            let client_id = NEXT_CLIENT_ID.fetch_add(1, Ordering::SeqCst);
            virtual_ip = Ipv4Addr::new(10, 0, 0, client_id as u8);
            tun_config = TunConfig {
                name: format!("tun{}", client_id),
                address: virtual_ip.to_string(),
                netmask: "255.255.255.0".to_string(),
                dns: vec!["114.114.114.114".to_string(), "8.8.8.8".to_string()],
                mtu: 1400,
            };
            info!(
                "Client {} created new session with session_id: {}, IP: {}",
                client_id, session_id, virtual_ip
            );
        }
    } else {
        session_id = build_session_id();
        let client_id = NEXT_CLIENT_ID.fetch_add(1, Ordering::SeqCst);
        virtual_ip = Ipv4Addr::new(10, 0, 0, client_id as u8);
        tun_config = TunConfig {
            name: format!("tun{}", client_id),
            address: virtual_ip.to_string(),
            netmask: "255.255.255.0".to_string(),
            dns: vec!["114.114.114.114".to_string(), "8.8.8.8".to_string()],
            mtu: 1400,
        };
        info!(
            "Client {} created new session with session_id: {}, IP: {}",
            client_id, session_id, virtual_ip
        );
    }

    let message = Message::handshake(Handshake {
        token: server_token.clone(),
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

    {
        let mut sessions_map = SESSIONS.lock().await;
        sessions_map.insert(session_id.clone(), client.clone());
    }

    info!(
        "Client connected from {}, assigned IP: {}, session_id: {}",
        src_addr, virtual_ip, session_id
    );
}

async fn handle_disconnect(addr: SocketAddr) {
    let mut sessions_map = SESSIONS.lock().await;
    if let Some((session_id, client)) = sessions_map
        .iter()
        .find(|(_k, v)| v.addr == addr)
        .map(|(k, v)| (k.clone(), v.clone()))
    {
        sessions_map.remove(&session_id);
        info!("Client {} disconnected ({})", session_id, client.addr);
    }
}

async fn handle_tun_packet(tun_rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>) {
    while let Some(data) = tun_rx.recv().await {
        let sessions_map = SESSIONS.lock().await;
        if let Some(dest_ip) = get_destination_ip(&data) {
            let target_client = sessions_map.values().find(|c| c.virtual_ip == dest_ip);
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
    session_id: &str,
) {
    let sessions_map = SESSIONS.lock().await;
    if let Some(client) = sessions_map.get(session_id) {
        let message = Message::data(Data {
            payload: data.to_vec(),
        });
        if let Err(e) = transport.send(message, client.addr).await {
            warn!("Failed to send to {}: {}", client.addr, e);
        }
    }
}

async fn udp_transport_io_task(
    mut transport: UdpTransport,
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
                                let (dummy_tx, _) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
                                let provided_session_id = if handshake.session_id.is_empty() {
                                    None
                                } else {
                                    Some(handshake.session_id.clone())
                                };
                                let provided_token = if handshake.token.is_empty() {
                                    None
                                } else {
                                    Some(handshake.token.clone())
                                };
                                handle_handshake(src_addr, &mut transport, dummy_tx, provided_session_id, provided_token).await;
                            }
                            Some(MessageType::Data(data)) => {
                                handle_data(&data.payload, &transport_tx).await;
                            }
                            Some(MessageType::Keepalive(keepalive)) => {
                                handle_keepalive(src_addr, &mut transport, keepalive.timestamp).await;
                            }
                            Some(MessageType::Disconnect(disconnect)) => {
                                handle_disconnect(src_addr).await;
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
                        let sessions_map = SESSIONS.lock().await;
                        if let Some(dest_ip) = get_destination_ip(&data) {
                            let target_client = sessions_map.values().find(|c| c.virtual_ip == dest_ip);
                            if let Some(client) = target_client {
                                send_to_client(&data, &mut transport, client.session_id.as_str()).await;
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
    let routing_engine = load_routing_engine(config.rules_path.as_deref(), "server")?;

    let transport = UdpTransport::bind(&config.bind_addr).await?;

    let tun_handle = tokio::spawn(tun_io_task(
        tun,
        tun_tx,
        transport_rx,
        routing_engine,
        "server",
    ));
    let transport_handle = tokio::spawn(udp_transport_io_task(transport, tun_rx, transport_tx));

    tokio::select! {
        _ = tun_handle => {},
        _ = transport_handle => {},
    }
    Ok(())
}

async fn handle_tcp_connection(
    mut tcp_transport: TcpTransport,
    transport_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
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
                                let provided_token = if handshake.token.is_empty() {
                                    None
                                } else {
                                    Some(handshake.token.clone())
                                };
                                handle_handshake(peer_addr, &mut tcp_transport, client_tx.clone(), provided_session_id, provided_token).await;
                            }
                            Some(MessageType::Data(data)) => {
                                handle_data(&data.payload, &transport_tx).await;
                            }
                            Some(MessageType::Keepalive(keepalive)) => {
                                handle_keepalive(src_addr, &mut tcp_transport, keepalive.timestamp).await;
                            }
                            Some(MessageType::Disconnect(disconnect)) => {
                                handle_disconnect(src_addr).await;
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

    handle_disconnect(peer_addr).await;
}

async fn run_tcp_server(config: ServerConfig, tun: tun2::AsyncDevice) -> Result<()> {
    let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let (transport_tx, transport_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let routing_engine = load_routing_engine(config.rules_path.as_deref(), "server")?;
    let tun_handle = tokio::spawn(tun_io_task(
        tun,
        tun_tx,
        transport_rx,
        routing_engine,
        "server",
    ));

    tokio::spawn(async move {
        handle_tun_packet(&mut tun_rx).await;
    });

    let accept_task = tokio::spawn(async move {
        let listener = TcpTransport::bind(&config.bind_addr)
            .await
            .expect("Failed to bind to address");
        info!("TCP server listening on {}", config.bind_addr);

        loop {
            match TcpTransport::accept(&listener).await {
                Ok(tcp_transport) => {
                    let _client_id = NEXT_CLIENT_ID.fetch_add(1, Ordering::SeqCst);

                    let tx = transport_tx.clone();

                    tokio::spawn(async move { handle_tcp_connection(tcp_transport, tx).await });
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
    transport_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
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
                                let provided_token = if handshake.token.is_empty() {
                                    None
                                } else {
                                    Some(handshake.token.clone())
                                };
                                handle_handshake(peer_addr, &mut ws_transport, client_tx.clone(), provided_session_id, provided_token).await;
                            }
                            Some(MessageType::Data(data)) => {
                                handle_data(&data.payload, &transport_tx).await;
                            }
                            Some(MessageType::Keepalive(keepalive)) => {
                                handle_keepalive(src_addr, &mut ws_transport, keepalive.timestamp).await;
                            }
                            Some(MessageType::Disconnect(disconnect)) => {
                                handle_disconnect(src_addr).await;
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

    handle_disconnect(peer_addr).await;
}

async fn run_ws_server(config: ServerConfig, tun: tun2::AsyncDevice) -> Result<()> {
    let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let (transport_tx, transport_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let routing_engine = load_routing_engine(config.rules_path.as_deref(), "server")?;

    let tls_acceptor = if config.transport_type == "wss" {
        Some(WsTransport::create_tls_acceptor(&config.cert_path, &config.key_path).unwrap())
    } else {
        None
    };

    let tun_handle = tokio::spawn(tun_io_task(
        tun,
        tun_tx,
        transport_rx,
        routing_engine,
        "server",
    ));

    tokio::spawn(async move {
        handle_tun_packet(&mut tun_rx).await;
    });

    let accept_task = tokio::spawn(async move {
        let listener = WsTransport::bind(&config.bind_addr)
            .await
            .expect("Failed to bind to address");

        loop {
            match WsTransport::accept(&listener, tls_acceptor.as_ref().map(|a| a.clone())).await {
                Ok(ws_transport) => {
                    let tx = transport_tx.clone();

                    tokio::spawn(async move { handle_ws_connection(ws_transport, tx).await });
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
            Err(anyhow::anyhow!(
                "Unknown transport type: {}",
                config.transport_type
            ))
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
    token: Option<String>,
    rules: Option<String>,
) -> Result<()> {
    let mut config: ServerConfig = ServerConfig::load()?;

    if let Some(transport_type) = transport_type {
        config.transport_type = transport_type;
    }

    if let Some(bind_addr) = bind_addr {
        config.bind_addr = bind_addr;
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

    if let Some(token) = token {
        config.token = token;
    }

    if let Some(rules_path) = rules {
        config.rules_path = Some(rules_path);
    }

    config.save()?;

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
            let elapsed = now
                .duration_since(client.last_seen)
                .unwrap_or(Duration::MAX);
            let should_keep = elapsed < Duration::from_secs(3600);

            if !should_keep {
                info!(
                    "Cleaning up expired session: {}, last seen: {:?}",
                    session_id, client.last_seen
                );
                removed_count += 1;
            }

            should_keep
        });

        if removed_count > 0 {
            info!("Cleaned up {} expired sessions", removed_count);
        }
    }
}
