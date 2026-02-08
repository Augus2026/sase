use crate::common::{ClientConfig, PacketType, VpnPacket, TUN_MTU, tun_io_task, configure_udp_socket};
use anyhow::Result;
use log::{debug, error, info, warn};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{interval, sleep};
use tun2::{create_as_async, Configuration};
use std::net::UdpSocket as StdUdpSocket;

async fn handshake_async(socket: &UdpSocket, server_addr: std::net::SocketAddr) -> Result<u32> {
    info!("Connecting to server at {}", server_addr);

    let handshake_packet = VpnPacket::new(PacketType::Handshake, 0, 0, 0);
    let handshake_buf = handshake_packet.to_bytes();

    let mut retry_delay = Duration::from_secs(1);
    let max_retry_delay = Duration::from_secs(300);
    let mut attempt = 0u32;

    loop {
        attempt += 1;
        info!("Handshake attempt {} to {}", attempt, server_addr);

        socket.send_to(&handshake_buf, server_addr).await?;
        debug!("Handshake sent to {}", server_addr);

        let timeout = sleep(Duration::from_secs(5));
        tokio::pin!(timeout);

        let mut recv_buf = [0u8; VpnPacket::HEADER_SIZE];

        tokio::select! {
            result = socket.recv_from(&mut recv_buf) => {
                match result {
                    Ok((n, addr)) => {
                        if addr == server_addr {
                            match VpnPacket::from_bytes(&recv_buf[..n]) {
                                Ok(header) if header.packet_type == PacketType::Handshake => {
                                    info!("Connected! Client ID: {}", header.client_id);
                                    return Ok(header.client_id);
                                }
                                _ => {
                                    debug!("Unexpected packet during handshake");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Error during handshake attempt {}: {}", attempt, e);
                    }
                }
            }
            _ = &mut timeout => {
                debug!("Handshake attempt {} timed out", attempt);
            }
        }

        warn!("Connection failed, retrying in {}s...", retry_delay.as_secs());
        sleep(retry_delay).await;
        retry_delay = std::cmp::min(retry_delay * 2, max_retry_delay);
    }
}

struct VpnClient {
    socket: Arc<UdpSocket>,
    server_addr: std::net::SocketAddr,
    client_id: u32,
    sequence: u32,
    tun_tx: mpsc::Sender<Vec<u8>>,
}

impl VpnClient {
    fn new(
        socket: Arc<UdpSocket>,
        server_addr: std::net::SocketAddr,
        client_id: u32,
        tun_tx: mpsc::Sender<Vec<u8>>,
    ) -> Self {
        Self {
            socket,
            server_addr,
            client_id,
            sequence: 0,
            tun_tx,
        }
    }

    async fn handle_data_from_server(&self, header: &VpnPacket, udp_buf: &[u8], packet_size: usize) -> bool {
        let payload_start = VpnPacket::HEADER_SIZE;
        let payload_end = payload_start + header.length as usize;

        if payload_end <= packet_size {
            let payload = udp_buf[payload_start..payload_end].to_vec();
            if let Err(e) = self.tun_tx.send(payload).await {
                error!("UDP: Failed to send to TUN: {}", e);
                return false;
            }
        }

        true
    }

    async fn handle_keepalive_from_server(&self) {
        debug!("Keepalive received from server");
    }

    async fn handle_disconnect_from_server(&self) -> bool {
        warn!("Server disconnected");
        false
    }

    async fn send_data_to_server(&mut self, data: Vec<u8>) {
        let packet = VpnPacket::new(PacketType::Data, self.client_id, self.sequence, data.len() as u16);
        self.sequence = self.sequence.wrapping_add(1);

        let mut send_buf = vec![0u8; VpnPacket::HEADER_SIZE + data.len()];
        send_buf[..VpnPacket::HEADER_SIZE].copy_from_slice(&packet.to_bytes());
        send_buf[VpnPacket::HEADER_SIZE..].copy_from_slice(&data);

        if let Err(e) = self.socket.send_to(&send_buf, self.server_addr).await {
            warn!("UDP: Failed to send to server: {}", e);
        }
    }

    async fn send_keepalive_to_server(&mut self) {
        let packet = VpnPacket::new(PacketType::KeepAlive, self.client_id, self.sequence, 0);
        self.sequence = self.sequence.wrapping_add(1);
        let buf = packet.to_bytes();

        if let Err(e) = self.socket.send_to(&buf, self.server_addr).await {
            warn!("Keepalive: Failed to send: {}", e);
        }
    }

    async fn process_udp_packet(&mut self, udp_buf: &[u8], packet_size: usize, src_addr: std::net::SocketAddr) -> bool {
        if src_addr != self.server_addr {
            debug!("UDP: Received packet from unexpected address: {}", src_addr);
            return true;
        }

        if packet_size < VpnPacket::HEADER_SIZE {
            debug!("UDP: Received short packet");
            return true;
        }

        match VpnPacket::from_bytes(&udp_buf[..packet_size]) {
            Ok(header) => {
                if header.client_id != self.client_id {
                    return true;
                }

                match header.packet_type {
                    PacketType::Data => {
                        self.handle_data_from_server(&header, udp_buf, packet_size).await
                    }
                    PacketType::KeepAlive => {
                        self.handle_keepalive_from_server().await;
                        true
                    }
                    PacketType::Disconnect => {
                        self.handle_disconnect_from_server().await
                    }
                    _ => true,
                }
            }
            Err(e) => {
                debug!("UDP: Failed to parse packet: {}", e);
                true
            }
        }
    }

    async fn run(&mut self, mut tun_rx: mpsc::Receiver<Vec<u8>>) {
        let mut udp_buf = vec![0u8; VpnPacket::HEADER_SIZE + TUN_MTU];
        let mut keepalive_interval = interval(Duration::from_secs(10));
        info!("UDP I/O task started for client {}", self.client_id);

        loop {
            tokio::select! {
                result = self.socket.recv_from(&mut udp_buf) => {
                    match result {
                        Ok((n, src_addr)) => {
                            if !self.process_udp_packet(&udp_buf, n, src_addr).await {
                                break;
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
                            self.send_data_to_server(data).await;
                        }
                        None => {
                            error!("UDP: Channel disconnected");
                            break;
                        }
                    }
                }

                _ = keepalive_interval.tick() => {
                    self.send_keepalive_to_server().await;
                }
            }
        }
    }
}

pub async fn run_client(config: ClientConfig) -> Result<()> {
    info!("Creating TUN device: {}", config.tun_name);

    let mut tun_config = Configuration::default();
    tun_config
        .tun_name(&config.tun_name)
        .layer(tun2::Layer::L3)
        .mtu(config.mtu as u16)
        .address(config.tun_addr)
        .netmask(config.tun_netmask)
        .up();

    let tun = create_as_async(&tun_config)?;
    info!("TUN device created: {} -> {}", config.tun_name, config.tun_addr);

    let std_socket = StdUdpSocket::bind("0.0.0.0:0")?;
    std_socket.set_nonblocking(true)?;

    let socket = configure_udp_socket(std_socket, config.socket_recv_buffer_size, config.socket_send_buffer_size)?;

    let client_id = handshake_async(&socket, config.server_addr).await?;
    info!("Client {} ready, tunnel established to {}", client_id, config.server_addr);

    let (tun_to_udp_tx, tun_to_udp_rx) = mpsc::channel::<Vec<u8>>(4096);
    let (udp_to_tun_tx, udp_to_tun_rx) = mpsc::channel::<Vec<u8>>(4096);

    let tun_handle = tokio::spawn(
        tun_io_task(
            tun,
            tun_to_udp_tx,
            udp_to_tun_rx
        )
    );

    let mut client = VpnClient::new(
        Arc::clone(&socket),
        config.server_addr,
        client_id,
        udp_to_tun_tx,
    );
    let udp_handle = tokio::spawn(async move {
        client.run(tun_to_udp_rx).await
    });
    info!("Client {} is running, press Ctrl+C to stop", client_id);

    tokio::signal::ctrl_c().await?;
    info!("Shutting down client {}...", client_id);

    tun_handle.abort();
    udp_handle.abort();

    Ok(())
}

pub async fn run_client_with_args(
    server: Option<String>,
    tun: Option<String>,
    address: Option<String>,
    netmask: Option<String>,
    mtu: Option<usize>,
    recv_buffer: Option<usize>,
    send_buffer: Option<usize>,
) -> Result<()> {
    let mut config = ClientConfig::default();

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

    if let Some(recv_buffer_mb) = recv_buffer {
        config.socket_recv_buffer_size = recv_buffer_mb * 1024 * 1024;
    }

    if let Some(send_buffer_mb) = send_buffer {
        config.socket_send_buffer_size = send_buffer_mb * 1024 * 1024;
    }

    debug!("Client configuration: {:?}", config);

    run_client(config).await
}
