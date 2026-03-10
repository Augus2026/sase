use crate::common::{ClientConfig, tun_io_task, print_packet_info};
use crate::transport::{TransportTrait, TcpTransport, UdpTransport};
use crate::codec::{Message, MessageType};
use anyhow::Result;
use log::{debug, error, info, warn};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{interval, sleep};
use tun2::{create_as_async, Configuration};

#[derive(Debug, Clone)]
struct TunConfig {
    pub name: String,
    pub address: String,
    pub netmask: String,
    pub dns: Vec<String>,
    pub mtu: u32,
}

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
        info!("Handshake sent to {}", server_addr);

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

                                        // 解析TunConfig
                                        debug!("Received handshake data (total {} bytes): {:?}", msg.data.len(), msg.data);
                                        debug!("Client ID: {}, remaining data for TunConfig: {} bytes", client_id, msg.data.len() - 4);
                                        debug!("TunConfig data: {:?}", &msg.data[4..]);

                                        if let Some(tun_config) = parse_tun_config(&msg.data[4..]) {
                                            info!("Received TUN config: name={}, address={}, netmask={}, mtu={}",
                                                  tun_config.name, tun_config.address, tun_config.netmask, tun_config.mtu);
                                            return Ok((client_id, tun_config));
                                        } else {
                                            warn!("Failed to parse TUN config from handshake response");
                                            warn!("Raw data: {:?}", &msg.data);
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

fn parse_tun_config(data: &[u8]) -> Option<TunConfig> {
    let mut pos = 0;

    debug!("parse_tun_config: Starting with {} bytes", data.len());
    debug!("parse_tun_config: Raw data: {:?}", data);

    // Parse name (null-terminated string)
    let name_end = data[pos..].iter().position(|&b| b == 0)?;
    let name = String::from_utf8(data[pos..pos + name_end].to_vec()).ok()?;
    debug!("parse_tun_config: name='{}', pos={}", name, pos);
    pos += name_end + 1;

    // Parse address (null-terminated string)
    if pos >= data.len() {
        warn!("parse_tun_config: Reached end of data while parsing address");
        return None;
    }
    let address_end = data[pos..].iter().position(|&b| b == 0)?;
    let address = String::from_utf8(data[pos..pos + address_end].to_vec()).ok()?;
    debug!("parse_tun_config: address='{}', pos={}", address, pos);
    pos += address_end + 1;

    // Parse netmask (null-terminated string)
    if pos >= data.len() {
        warn!("parse_tun_config: Reached end of data while parsing netmask");
        return None;
    }
    let netmask_end = data[pos..].iter().position(|&b| b == 0)?;
    let netmask = String::from_utf8(data[pos..pos + netmask_end].to_vec()).ok()?;
    debug!("parse_tun_config: netmask='{}', pos={}", netmask, pos);
    pos += netmask_end + 1;

    // Parse DNS entries (multiple null-terminated strings until we reach the mtu)
    let mut dns = Vec::new();
    debug!("parse_tun_config: Starting DNS parsing at pos={}", pos);

    while pos + 4 < data.len() { // Need at least 4 bytes for mtu after DNS
        if pos >= data.len() {
            break;
        }

        let dns_end = data[pos..].iter().position(|&b| b == 0)?;
        if dns_end == 0 {
            pos += 1; // Skip consecutive null terminators
            continue;
        }
        if pos + dns_end + 1 > data.len() - 4 {
            debug!("parse_tun_config: Not enough space for DNS + null terminator + mtu");
            break;
        }
        let dns_str = String::from_utf8(data[pos..pos + dns_end].to_vec()).ok()?;
        if !dns_str.is_empty() {
            debug!("parse_tun_config: DNS entry='{}', pos={}", dns_str, pos);
            dns.push(dns_str);
        }
        pos += dns_end + 1;
    }

    debug!("parse_tun_config: DNS parsing complete at pos={}", pos);

    // Parse MTU (4 bytes)
    if pos + 4 > data.len() {
        warn!("parse_tun_config: Not enough data for MTU at pos={}, data.len()={}", pos, data.len());
        return None;
    }
    let mtu = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    debug!("parse_tun_config: mtu={}", mtu);

    Some(TunConfig {
        name,
        address,
        netmask,
        dns,
        mtu,
    })
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
                                    info!("Keepalive received from server (no latency measurement)");
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

pub async fn run_client(config: ClientConfig, transport_type: String) -> Result<()> {
    info!("Connecting to server to get TUN configuration...");

    match transport_type.to_lowercase().as_str() {
        "tcp" => {
            info!("Using TCP transport");
            let mut transport = TcpTransport::connect(config.server_addr.to_string().as_str()).await?;
            let (client_id, tun_config) = handshake_async(&mut transport, config.server_addr).await?;

            info!("Creating TUN device with server config: {}", tun_config.name);

            let address: std::net::Ipv4Addr = tun_config.address.parse()?;
            let netmask: std::net::Ipv4Addr = tun_config.netmask.parse()?;

            let mut tun_config_builder = Configuration::default();
            tun_config_builder
                .tun_name(&tun_config.name)
                .layer(tun2::Layer::L3)
                .mtu(tun_config.mtu as u16)
                .address(address)
                .netmask(netmask)
                .up();

            let tun_device = create_as_async(&tun_config_builder)?;
            info!("TUN device created: {} -> {}", tun_config.name, tun_config.address);

            run_tcp_client(config, tun_device, transport, client_id).await?;
        }
        "udp" => {
            info!("Using UDP transport");
            let mut transport = UdpTransport::bind("0.0.0.0:0").await?;
            let (client_id, tun_config) = handshake_async(&mut transport, config.server_addr).await?;

            info!("Creating TUN device with server config: {}", tun_config.name);

            let address: std::net::Ipv4Addr = tun_config.address.parse()?;
            let netmask: std::net::Ipv4Addr = tun_config.netmask.parse()?;

            let mut tun_config_builder = Configuration::default();
            tun_config_builder
                .tun_name(&tun_config.name)
                .layer(tun2::Layer::L3)
                .mtu(tun_config.mtu as u16)
                .address(address)
                .netmask(netmask)
                .up();

            let tun_device = create_as_async(&tun_config_builder)?;
            info!("TUN device created: {} -> {}", tun_config.name, tun_config.address);

            run_udp_client(config, tun_device, transport, client_id).await?;
        }
        _ => {
            error!("Unknown transport type: {}", transport_type);
            return Err(anyhow::anyhow!("Unknown transport type: {}", transport_type));
        }
    }

    Ok(())
}

pub async fn run_client_with_args(
    server: Option<String>,
    tun: Option<String>,
    address: Option<String>,
    netmask: Option<String>,
    mtu: Option<usize>,
    transport: Option<String>,
) -> Result<()> {
    let mut config = ClientConfig::default();
    let transport_type = transport.unwrap_or_else(|| "udp".to_string());

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

    info!("Client configuration: {:?}", config);
    info!("Transport protocol: {}", transport_type);

    run_client(config, transport_type).await
}
