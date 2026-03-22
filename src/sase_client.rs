use crate::common::{ClientConfig, tun_io_task, print_packet_info};
use crate::transport::{TransportTrait, TcpTransport, UdpTransport, WsTransport};
use crate::codec::{Message, MessageType};
use crate::tun_config::{TunConfig, deserialize_tun_config, create_tun_device};
use anyhow::Result;
use log::{error, info, warn};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{interval, sleep};

async fn handshake_async(
    transport: &mut impl TransportTrait<Error = std::io::Error>,
    server_addr: std::net::SocketAddr,
) -> Result<(u32, TunConfig)> {
    info!("Connecting to server at {}", server_addr);
    let handshake_message = Message::handshake(vec![]);
    let mut retry_delay = Duration::from_secs(1);
    let max_retry_delay = Duration::from_secs(300);
    let mut attempt = 0u32;

    loop {
        attempt += 1;
        info!("Handshake attempt {} to {}", attempt, server_addr);

        transport.send(handshake_message.clone(), server_addr).await?;

        let timeout = sleep(Duration::from_secs(5));
        tokio::pin!(timeout);

        tokio::select! {
            result = transport.next() => {
                match result {
                    Some(Ok((msg, addr))) => {
                        if addr == server_addr {
                            match MessageType::try_from(msg.message_type) {
                                Ok(MessageType::Handshake) => {
                                    if msg.data.len() >= 4 {
                                        let client_id = u32::from_be_bytes([msg.data[0], msg.data[1], msg.data[2], msg.data[3]]);
                                        info!("Connected! Client ID: {}", client_id);

                                        if let Some(tun_config) = deserialize_tun_config(&msg.data[4..]) {
                                            info!("Received TUN config: name={}, address={}, netmask={}, mtu={}",
                                                  tun_config.name, tun_config.address, tun_config.netmask, tun_config.mtu);
                                            return Ok((client_id, tun_config));
                                        } else {
                                            return Err(anyhow::anyhow!("Invalid TUN config in handshake response"));
                                        }
                                    }
                                }
                                _ => {
                                    info!("Invalid handshake response: unexpected message type: {}", msg.message_type);
                                }
                            }
                        }
                    }
                    Some(Err(e)) => {
                        info!("Error during handshake attempt {}: {}", attempt, e);
                    }
                    None => {}
                }
            }
            _ = &mut timeout => {
                info!("Handshake attempt {} timed out", attempt);
            }
        }

        warn!("Connection failed, retrying in {}s...", retry_delay.as_secs());
        sleep(retry_delay).await;
        retry_delay = std::cmp::min(retry_delay * 2, max_retry_delay);
    }
}

async fn transport_io_task<T>(
    mut transport: T,
    server_addr: std::net::SocketAddr,
    client_id: u32,
    mut tun_rx: mpsc::Receiver<Vec<u8>>,
    transport_tx: mpsc::Sender<Vec<u8>>,
)
where
    T: TransportTrait<Error = std::io::Error>,
{
    let mut keepalive_interval = interval(Duration::from_millis(3000));
    info!("Transport I/O task started for client {}", client_id);

    loop {
        tokio::select! {
            result = transport.next() => {
                match result {
                    Some(Ok((msg, src_addr))) => {
                        if src_addr != server_addr {
                            info!("Transport: Received packet from unexpected address: {}", src_addr);
                            continue;
                        }

                        match MessageType::try_from(msg.message_type) {
                            Ok(MessageType::Data) => {
                                print_packet_info("[transport recv]", &msg.data);
                                if let Err(e) = transport_tx.send(msg.data).await {
                                    error!("Transport: Failed to send to TUN: {}", e);
                                    break;
                                }
                            }
                            Ok(MessageType::KeepAlive) => {
                                if msg.data.len() >= 8 {
                                    let sent_timestamp = u64::from_be_bytes([
                                        msg.data[0], msg.data[1], msg.data[2], msg.data[3],
                                        msg.data[4], msg.data[5], msg.data[6], msg.data[7],
                                    ]);
                                    let received_timestamp = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap()
                                        .as_millis() as u64;
                                    let latency_ms = received_timestamp - sent_timestamp;
                                    info!("Keepalive received from server, latency: {}ms", latency_ms);
                                } else {
                                    info!("Keepalive received from server");
                                }
                            }
                            Ok(MessageType::Disconnect) => {
                                warn!("Server disconnected");
                                break;
                            }
                            _ => {
                                info!("Transport: Unknown message type: {}", msg.message_type);
                            }
                        }
                    }
                    Some(Err(e)) => {
                        error!("Transport: Error receiving: {}", e);
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
                        print_packet_info("[transport send]", &data);
                        let message = Message::data(data);
                        if let Err(e) = transport.send(message, server_addr).await {
                            error!("Transport: Failed to send to server: {}", e);
                            break;
                        }
                    }
                    None => {
                        error!("Transport: Channel disconnected");
                        break;
                    }
                }
            }

            _ = keepalive_interval.tick() => {
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                let timestamp_bytes = timestamp.to_be_bytes().to_vec();
                let message = Message::keepalive(timestamp_bytes);
                if let Err(e) = transport.send(message, server_addr).await {
                    error!("Keepalive: Failed to send: {}", e);
                    break;
                }
            }
        }
    }
}

pub async fn run_tcp_client(config: ClientConfig, tun: tun2::AsyncDevice, transport: TcpTransport, client_id: u32) -> Result<()> {
    let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>(4096);
    let (transport_tx, transport_rx) = mpsc::channel::<Vec<u8>>(4096);

    let tun_handle = tokio::spawn(
        tun_io_task(
            tun,
            tun_tx,
            transport_rx
        )
    );
    let transport_handle = tokio::spawn(
        transport_io_task(
            transport,
            config.server_addr,
            client_id,
            tun_rx,
            transport_tx,
        )
    );

    tokio::select! {
        _ = tun_handle => {},
        _ = transport_handle => {},
    }
    Ok(())
}

pub async fn run_udp_client(config: ClientConfig, tun: tun2::AsyncDevice, transport: UdpTransport, client_id: u32) -> Result<()> {
    let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>(4096);
    let (transport_tx, transport_rx) = mpsc::channel::<Vec<u8>>(4096);

    let tun_handle = tokio::spawn(
        tun_io_task(
            tun,
            tun_tx,
            transport_rx
        )
    );
    let transport_handle = tokio::spawn(
        transport_io_task(
            transport,
            config.server_addr,
            client_id,
            tun_rx,
            transport_tx,
        )
    );

    tokio::select! {
        _ = tun_handle => {},
        _ = transport_handle => {},
    }
    Ok(())
}

pub async fn run_ws_client(_config: ClientConfig, tun: tun2::AsyncDevice, transport: WsTransport, client_id: u32) -> Result<()> {
    let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>(4096);
    let (transport_tx, transport_rx) = mpsc::channel::<Vec<u8>>(4096);

    let server_addr = transport.server_addr();

    let tun_handle = tokio::spawn(
        tun_io_task(
            tun,
            tun_tx,
            transport_rx
        )
    );
    let transport_handle = tokio::spawn(
        transport_io_task(
            transport,
            server_addr,
            client_id,
            tun_rx,
            transport_tx,
        )
    );

    tokio::select! {
        _ = tun_handle => {},
        _ = transport_handle => {},
    }
    Ok(())
}

pub async fn run_client(config: ClientConfig) -> Result<()> {
    info!("Connecting to server to get TUN configuration...");

    match config.transport_type.to_lowercase().as_str() {
        "tcp" => {
            info!("Using TCP transport");

            let mut transport = TcpTransport::connect(config.server_addr.to_string().as_str()).await?;
            let (client_id, tun_config) = handshake_async(&mut transport, config.server_addr).await?;

            info!("Creating TUN device with server config: {}", tun_config.name);
            let tun_device = create_tun_device(&tun_config)?;

            run_tcp_client(config, tun_device, transport, client_id).await?;
        }
        "udp" => {
            info!("Using UDP transport");

            let mut transport = UdpTransport::bind("0.0.0.0:0").await?;
            let (client_id, tun_config) = handshake_async(&mut transport, config.server_addr).await?;

            info!("Creating TUN device with server config: {}", tun_config.name);
            let tun_device = create_tun_device(&tun_config)?;

            run_udp_client(config, tun_device, transport, client_id).await?;
        }
        "ws" => {
            info!("Using WebSocket transport");

            let ws_url = format!("ws://{}", config.server_addr);
            let mut transport = WsTransport::connect(&ws_url, &config.ca_cert_path).await?;
            let server_addr = transport.server_addr();
            let (client_id, tun_config) = handshake_async(&mut transport, server_addr).await?;

            info!("Creating TUN device with server config: {}", tun_config.name);
            let tun_device = create_tun_device(&tun_config)?;

            run_ws_client(config, tun_device, transport, client_id).await?;
        }
        "wss" => {
            info!("Using WebSocket(Secure) transport");

            let wss_url = format!("wss://{}", config.server_addr);
            let mut transport = WsTransport::connect(&wss_url, &config.ca_cert_path).await?;
            let server_addr = transport.server_addr();
            let (client_id, tun_config) = handshake_async(&mut transport, server_addr).await?;

            info!("Creating TUN device with server config: {}", tun_config.name);
            let tun_device = create_tun_device(&tun_config)?;

            run_ws_client(config, tun_device, transport, client_id).await?;
        }
        _ => {
            error!("Unknown transport type: {}", config.transport_type);
            return Err(anyhow::anyhow!("Unknown transport type: {}", config.transport_type));
        }
    }

    Ok(())
}

pub async fn run_client_with_args(
    transport_type: Option<String>,
    server_addr: Option<String>,
    ca_cert_path: Option<String>,
) -> Result<()> {
    let mut config = ClientConfig::default();

    if let Some(transport_type) = transport_type {
        config.transport_type = transport_type;
    }

    if let Some(server_addr) = server_addr {
        config.server_addr = server_addr.parse()?;
    }

    if let Some(ca_cert_path) = ca_cert_path {
        config.ca_cert_path = ca_cert_path;
    }

    info!("Client configuration: {:?}", config);

    run_client(config).await
}
