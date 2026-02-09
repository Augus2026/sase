use anyhow::Result;
use log::{debug, info, warn, error};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::net::UdpSocket as StdUdpSocket;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

/// VPN protocol configuration
pub const SERVER_ADDR: &str = "0.0.0.0";
pub const SERVER_PORT: u16 = 12345;
pub const TUN_NAME: &str = "tun0";
pub const TUN_MTU: usize = 1500;

/// Protocol magic number for identification
pub const PROTOCOL_MAGIC: u32 = 0x53415345; // "SASE"

/// Packet types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Data = 0x01,
    Handshake = 0x02,
    KeepAlive = 0x03,
    Disconnect = 0x04,
}

impl PacketType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(PacketType::Data),
            0x02 => Some(PacketType::Handshake),
            0x03 => Some(PacketType::KeepAlive),
            0x04 => Some(PacketType::Disconnect),
            _ => None,
        }
    }
}

/// VPN packet header
#[derive(Debug, Clone)]
pub struct VpnPacket {
    pub magic: u32,
    pub packet_type: PacketType,
    pub client_id: u32,
    pub sequence: u32,
    pub length: u16,
}

impl VpnPacket {
    pub const HEADER_SIZE: usize = 15; // 4 + 1 + 4 + 4 + 2 = 15

    pub fn new(packet_type: PacketType, client_id: u32, sequence: u32, length: u16) -> Self {
        Self {
            magic: PROTOCOL_MAGIC,
            packet_type,
            client_id,
            sequence,
            length,
        }
    }

    pub fn to_bytes(&self) -> [u8; Self::HEADER_SIZE] {
        let mut buf = [0u8; Self::HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.magic.to_be_bytes());
        buf[4] = self.packet_type as u8;
        buf[5..9].copy_from_slice(&self.client_id.to_be_bytes());
        buf[9..13].copy_from_slice(&self.sequence.to_be_bytes());
        buf[13..15].copy_from_slice(&self.length.to_be_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::HEADER_SIZE {
            anyhow::bail!("Packet too short");
        }

        let magic = u32::from_be_bytes(data[0..4].try_into()?);
        if magic != PROTOCOL_MAGIC {
            anyhow::bail!("Invalid magic number");
        }

        let packet_type = PacketType::from_u8(data[4])
            .ok_or_else(|| anyhow::anyhow!("Invalid packet type"))?;

        let client_id = u32::from_be_bytes(data[5..9].try_into()?);
        let sequence = u32::from_be_bytes(data[9..13].try_into()?);
        let length = u16::from_be_bytes(data[13..15].try_into()?);

        Ok(Self {
            magic,
            packet_type,
            client_id,
            sequence,
            length,
        })
    }
}

/// Client configuration
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub server_addr: SocketAddr,
    pub tun_name: String,
    pub tun_addr: Ipv4Addr,
    pub tun_netmask: Ipv4Addr,
    pub mtu: usize,
    pub socket_recv_buffer_size: usize,
    pub socket_send_buffer_size: usize,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:9999".parse().unwrap(),
            tun_name: "tun0".to_string(),
            tun_addr: Ipv4Addr::new(10, 0, 0, 2),
            tun_netmask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: TUN_MTU,
            socket_recv_buffer_size: 8 * 1024 * 1024,
            socket_send_buffer_size: 8 * 1024 * 1024,
        }
    }
}

/// Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_addr: SocketAddr,
    pub tun_name: String,
    pub tun_addr: Ipv4Addr,
    pub tun_netmask: Ipv4Addr,
    pub mtu: usize,
    pub socket_recv_buffer_size: usize,
    pub socket_send_buffer_size: usize,
    pub transparent_proxy: TransparentProxyConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: format!("{}:{}", SERVER_ADDR, SERVER_PORT).parse().unwrap(),
            tun_name: TUN_NAME.to_string(),
            tun_addr: Ipv4Addr::new(10, 0, 0, 1),
            tun_netmask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: TUN_MTU,
            socket_recv_buffer_size: 8 * 1024 * 1024,
            socket_send_buffer_size: 8 * 1024 * 1024,
            transparent_proxy: TransparentProxyConfig::default(),
        }
    }
}

/// Print IP packet information for debugging
#[allow(dead_code)]
pub fn print_packet_info(prefix: &str, data: &[u8]) {
    if data.len() < 20 {
        warn!("{}: Packet too short ({:?} bytes)", prefix, data);
        return;
    }

    let ihl = ((data[0] & 0x0F) as usize) * 4;
    let protocol = data[9];
    let src_ip = std::net::Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = std::net::Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    let proto_name = match protocol {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        _ => "Other",
    };
    debug!("{}: {} {} -> {} ({} bytes)", prefix, proto_name, src_ip, dst_ip, data.len());

    match protocol {
        1 => {
            // ICMP
            if data.len() >= ihl + 8 {
                let icmp_type = data[ihl];
                let icmp_code = data[ihl + 1];
                let checksum = u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]);
                let id = u16::from_be_bytes([data[ihl + 4], data[ihl + 5]]);
                let seq = u16::from_be_bytes([data[ihl + 6], data[ihl + 7]]);

                let type_name = match icmp_type {
                    0 => "Echo Reply",
                    3 => "Destination Unreachable",
                    5 => "Redirect",
                    8 => "Echo Request",
                    11 => "Time Exceeded",
                    _ => "Unknown",
                };
                debug!("  └─ ICMP {} | type={}, code={}, checksum={}, id={}, seq={}",
                    type_name, icmp_type, icmp_code, checksum, id, seq);
            }
        }
        6 => {
            // TCP
            if data.len() >= ihl + 20 {
                let src_port = u16::from_be_bytes([data[ihl], data[ihl + 1]]);
                let dst_port = u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]);
                let seq = u32::from_be_bytes([data[ihl + 4], data[ihl + 5], data[ihl + 6], data[ihl + 7]]);
                let ack_num = u32::from_be_bytes([data[ihl + 8], data[ihl + 9], data[ihl + 10], data[ihl + 11]]);
                let flags = data[ihl + 13];
                let syn = (flags & 0x02) != 0;
                let ack_flag = (flags & 0x10) != 0;
                let fin = (flags & 0x01) != 0;
                let rst = (flags & 0x04) != 0;
                let psh = (flags & 0x08) != 0;
                debug!("  └─ TCP {} -> {} | SEQ={} ACK={} | flags:{}{}{}{}{}",
                    src_port, dst_port, seq, ack_num,
                    if syn { " SYN" } else { "" },
                    if ack_flag { " ACK" } else { "" },
                    if fin { " FIN" } else { "" },
                    if rst { " RST" } else { "" },
                    if psh { " PSH" } else { "" });
            }
        }
        17 => {
            // UDP
            if data.len() >= ihl + 8 {
                let src_port = u16::from_be_bytes([data[ihl], data[ihl + 1]]);
                let dst_port = u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]);
                let length = u16::from_be_bytes([data[ihl + 4], data[ihl + 5]]);
                debug!("  └─ UDP {} -> {} | length={}", src_port, dst_port, length);
            }
        }
        _ => {}
    }
}

/// Configure UDP socket with buffer sizes
pub fn configure_udp_socket(
    std_socket: StdUdpSocket,
    recv_buffer_size: usize,
    send_buffer_size: usize,
) -> Result<Arc<UdpSocket>> {
    let socket2_socket = socket2::Socket::from(std_socket);
    socket2_socket.set_recv_buffer_size(recv_buffer_size)?;
    socket2_socket.set_send_buffer_size(send_buffer_size)?;

    let actual_recv_size = socket2_socket.recv_buffer_size()?;
    let actual_send_size = socket2_socket.send_buffer_size()?;

    let local_addr = socket2_socket.local_addr()?.as_socket().expect("Failed to get socket address");
    info!("Socket bound to {} with recv_buffer={}MB (requested: {}MB), send_buffer={}MB (requested: {}MB)",
          local_addr,
          actual_recv_size / 1024 / 1024,
          recv_buffer_size / 1024 / 1024,
          actual_send_size / 1024 / 1024,
          send_buffer_size / 1024 / 1024);

    let socket = UdpSocket::from_std(socket2_socket.into())?;
    Ok(Arc::new(socket))
}

/// Common TUN I/O task for handling TUN device read/write operations
pub async fn tun_io_task(
    mut tun: tun2::AsyncDevice,
    tun_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    mut udp_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) {
    let mut tun_buf = vec![0u8; TUN_MTU];
    info!("TUN I/O task started");

    loop {
        tokio::select! {
            result = udp_rx.recv() => {
                match result {
                    Some(data) => {
                        print_packet_info("[tun write]", &data);
                        if let Err(e) = tun.write_all(&data).await {
                            error!("TUN I/O: Failed to write to TUN: {}", e);
                        }
                    }
                    None => {
                        error!("TUN I/O: Channel disconnected");
                        break;
                    }
                }
            }

            result = tun.read(&mut tun_buf) => {
                match result {
                    Ok(n) => {
                        let data = tun_buf[..n].to_vec();
                        print_packet_info("[tun read]", &data);
                        if let Err(e) = tun_tx.send(data).await {
                            error!("TUN I/O: Failed to send to UDP: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("TUN I/O: Error reading from TUN: {}", e);
                        break;
                    }
                }
            }
        }
    }
}

/// Transparent proxy configuration
#[derive(Debug, Clone)]
pub struct TransparentProxyConfig {
    pub enabled: bool,
    pub redirect_port: u16,
}

impl Default for TransparentProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            redirect_port: 1080,
        }
    }
}
