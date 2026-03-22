use crate::common::{ClientConfig, tun_io_task};
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
    info!("Handshake with server at {}", server_addr);
    let handshake_message = Message::handshake(vec![]);

    transport.send(handshake_message, server_addr).await?;

    let timeout = sleep(Duration::from_secs(5));
    tokio::pin!(timeout);

    tokio::select! {
        result = transport.next() => {
            match result {
                Some(Ok((msg, _addr))) => {
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
                            } else {
                                return Err(anyhow::anyhow!("Handshake response too short: expected at least 4 bytes"));
                            }
                        }
                        _ => {
                            return Err(anyhow::anyhow!("Invalid handshake response: unexpected message type: {}", msg.message_type));
                        }
                    }
                }
                Some(Err(e)) => {
                    return Err(anyhow::anyhow!("Error during handshake: {}", e));
                }
                None => {
                    return Err(anyhow::anyhow!("Transport closed during handshake"));
                }
            }
        }
        _ = &mut timeout => {
            return Err(anyhow::anyhow!("Handshake timed out"));
        }
    }
}

async fn transport_io_task<T>(
    mut transport: T,
    server_addr: std::net::SocketAddr,
    mut tun_rx: mpsc::Receiver<Vec<u8>>,
    transport_tx: mpsc::Sender<Vec<u8>>,
) -> anyhow::Result<()>
where
    T: TransportTrait<Error = std::io::Error>,
{
    let mut keepalive_interval = interval(Duration::from_millis(3000));
    loop {
        tokio::select! {
            result = transport.next() => {
                match result {
                    Some(Ok((msg, _addr))) => {
                        match MessageType::try_from(msg.message_type) {
                            Ok(MessageType::Data) => {
                                if let Err(e) = transport_tx.send(msg.data).await {
                                    return Err(anyhow::anyhow!("Failed to send to TUN: {}", e));
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
                                return Err(anyhow::anyhow!("Server disconnected"));
                            }
                            _ => {
                                info!("Transport: Unknown message type: {}", msg.message_type);
                            }
                        }
                    }
                    Some(Err(e)) => {
                        return Err(anyhow::anyhow!("Error receiving: {}", e));
                    }
                    None => {
                        return Err(anyhow::anyhow!("Connection closed"));
                    }
                }
            }

            result = tun_rx.recv() => {
                match result {
                    Some(data) => {
                        let message = Message::data(data);
                        if let Err(e) = transport.send(message, server_addr).await {
                            return Err(anyhow::anyhow!("Failed to send to server: {}", e));
                        }
                    }
                    None => {
                        return Err(anyhow::anyhow!("Channel disconnected"));
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
                    return Err(anyhow::anyhow!("Keepalive failed: {}", e));
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
            tun_rx,
            transport_tx,
        )
    );

    tokio::select! {
        result = tun_handle => {
            match result {
                Ok(Ok(())) => info!("TUN task completed successfully"),
                Ok(Err(e)) => {
                    return Err(anyhow::anyhow!("TUN task failed: {}", e));
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("TUN task panicked: {}", e));
                }
            }
        }
        result = transport_handle => {
            match result {
                Ok(Ok(())) => info!("Transport task completed successfully"),
                Ok(Err(e)) => {
                    return Err(anyhow::anyhow!("Transport task failed: {}", e));
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Transport task panicked: {}", e));
                }
            }
        }
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
            tun_rx,
            transport_tx,
        )
    );

    tokio::select! {
        result = tun_handle => {
            match result {
                Ok(Ok(())) => info!("TUN task completed successfully"),
                Ok(Err(e)) => {
                    return Err(anyhow::anyhow!("TUN task failed: {}", e));
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("TUN task panicked: {}", e));
                }
            }
        }
        result = transport_handle => {
            match result {
                Ok(Ok(())) => info!("Transport task completed successfully"),
                Ok(Err(e)) => {
                    return Err(anyhow::anyhow!("Transport task failed: {}", e));
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Transport task panicked: {}", e));
                }
            }
        }
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
            tun_rx,
            transport_tx,
        )
    );

    tokio::select! {
        result = tun_handle => {
            match result {
                Ok(Ok(())) => info!("TUN task completed successfully"),
                Ok(Err(e)) => {
                    return Err(anyhow::anyhow!("TUN task failed: {}", e));
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("TUN task panicked: {}", e));
                }
            }
        }
        result = transport_handle => {
            match result {
                Ok(Ok(())) => info!("Transport task completed successfully"),
                Ok(Err(e)) => {
                    return Err(anyhow::anyhow!("Transport task failed: {}", e));
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Transport task panicked: {}", e));
                }
            }
        }
    }
    Ok(())
}

pub async fn run_client(config: ClientConfig) -> Result<()> {
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

async fn run_client_with_retry(config: ClientConfig) -> Result<()> {
    let mut retry_delay = Duration::from_secs(1);
    let max_retry_delay = Duration::from_secs(300);
    let mut attempt = 0u32;

    loop {
        attempt += 1;
        info!("Client connection attempt {}...", attempt);

        match run_client(config.clone()).await {
            Ok(()) => {
                info!("Client completed successfully");
                return Ok(());
            }
            Err(e) => {
                error!("Client attempt {} failed: {}", attempt, e);
                warn!("Retrying in {}s...", retry_delay.as_secs());
                sleep(retry_delay).await;
                retry_delay = std::cmp::min(retry_delay * 2, max_retry_delay);
            }
        }
    }
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

    run_client_with_retry(config).await
}
