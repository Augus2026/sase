use anyhow::Result;
use std::net::{Ipv4Addr, SocketAddr};

/// VPN protocol configuration
pub const VPN_SERVER_PORT: u16 = 9999;
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
    pub const HEADER_SIZE: usize = 14; // 4 + 1 + 4 + 4 + 2 (rounded)

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
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:9999".parse().unwrap(),
            tun_name: "tun0".to_string(),
            tun_addr: Ipv4Addr::new(10, 0, 0, 2),
            tun_netmask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: TUN_MTU,
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
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:9999".parse().unwrap(),
            tun_name: "tun0".to_string(),
            tun_addr: Ipv4Addr::new(10, 0, 0, 1),
            tun_netmask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: TUN_MTU,
        }
    }
}
