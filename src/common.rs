use std::{net::Ipv4Addr, path::Path};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::routing::{
    context::PacketContext, decision::RoutingDecision, engine::HotReloadableEngine,
    rule::Protocol,
};

pub const SERVER_ADDR: &str = "127.0.0.1";
pub const SERVER_PORT: u16 = 12345;
pub const TUN_NAME: &str = "tun0";
pub const TUN_MTU: usize = 1500;

pub const CLIENT_CONFIG_PATH: &str = "client_config.json";
pub const SERVER_CONFIG_PATH: &str = "server_config.json";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClientConfig {
    pub transport_type: String,
    pub server_addr: String,
    pub ca_cert_path: String,
    pub session_id: String,
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules_path: Option<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            transport_type: "udp".to_string(),
            server_addr: format!("{}:{}", SERVER_ADDR, SERVER_PORT),
            ca_cert_path: "certs/ca-cert.pem".to_string(),
            session_id: String::new(),
            token: String::new(),
            rules_path: None,
        }
    }
}

impl ClientConfig {
    pub fn load_from_file(path: &str) -> anyhow::Result<Self> {
        if !Path::new(path).exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)?;
        let config = serde_json::from_str(&content)?;
        Ok(config)
    }

    pub fn save_to_file(&self, path: &str) -> anyhow::Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    pub fn load() -> anyhow::Result<Self> {
        Self::load_from_file(CLIENT_CONFIG_PATH)
    }

    pub fn save(&self) -> anyhow::Result<()> {
        self.save_to_file(CLIENT_CONFIG_PATH)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerConfig {
    pub transport_type: String,
    pub bind_addr: String,
    pub tun_name: String,
    pub tun_addr: Ipv4Addr,
    pub tun_netmask: Ipv4Addr,
    pub mtu: usize,
    pub cert_path: String,
    pub key_path: String,
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules_path: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            transport_type: "udp".to_string(),
            bind_addr: format!("{}:{}", SERVER_ADDR, SERVER_PORT),
            tun_name: TUN_NAME.to_string(),
            tun_addr: Ipv4Addr::new(10, 0, 0, 1),
            tun_netmask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: TUN_MTU,
            cert_path: "certs/server-cert.pem".to_string(),
            key_path: "certs/server-key.pem".to_string(),
            token: String::new(),
            rules_path: None,
        }
    }
}

impl ServerConfig {
    pub fn load_from_file(path: &str) -> anyhow::Result<Self> {
        if !Path::new(path).exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)?;
        let config = serde_json::from_str(&content)?;
        Ok(config)
    }

    pub fn save_to_file(&self, path: &str) -> anyhow::Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    pub fn load() -> anyhow::Result<Self> {
        Self::load_from_file(SERVER_CONFIG_PATH)
    }

    pub fn save(&self) -> anyhow::Result<()> {
        self.save_to_file(SERVER_CONFIG_PATH)
    }
}

pub async fn tun_io_task(
    mut tun: tun2::AsyncDevice,
    tun_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    mut transport_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> anyhow::Result<()> {
    let mut tun_buf = vec![0u8; TUN_MTU];
    loop {
        tokio::select! {
            result = transport_rx.recv() => {
                match result {
                    Some(data) => {
                        if let Err(e) = tun.write_all(&data).await {
                            return Err(anyhow::anyhow!("Failed to write to TUN: {}", e));
                        }
                    }
                    None => {
                        return Err(anyhow::anyhow!("Channel disconnected"));
                    }
                }
            }

            result = tun.read(&mut tun_buf) => {
                match result {
                    Ok(n) => {
                        let data = tun_buf[..n].to_vec();
                        if let Err(e) = tun_tx.send(data).await {
                            return Err(anyhow::anyhow!("Failed to send to transport: {}", e));
                        }
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!("Error reading from TUN: {}", e));
                    }
                }
            }
        }
    }
}

pub async fn tun_io_task_with_routing(
    mut tun: tun2::AsyncDevice,
    tun_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    mut transport_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    routing_engine: Option<HotReloadableEngine>,
) -> anyhow::Result<()> {
    let mut tun_buf = vec![0u8; TUN_MTU];
    loop {
        tokio::select! {
            result = transport_rx.recv() => {
                match result {
                    Some(data) => {
                        if let Err(e) = tun.write_all(&data).await {
                            return Err(anyhow::anyhow!("Failed to write to TUN: {}", e));
                        }
                    }
                    None => {
                        return Err(anyhow::anyhow!("Channel disconnected"));
                    }
                }
            }

            result = tun.read(&mut tun_buf) => {
                match result {
                    Ok(n) => {
                        let data = tun_buf[..n].to_vec();

                        if let Some(ref engine) = routing_engine {
                            if let Some(packet_ctx) = PacketContext::from_ip_packet(&data) {
                                let decision = engine.match_packet(&packet_ctx);
                                if decision.is_drop() {
                                    log::debug!(
                                        "[DROP] Packet dropped: src={} dst={} action={}",
                                        packet_ctx.src_ip,
                                        packet_ctx.dst_ip,
                                        decision
                                    );
                                    continue;
                                }
                            }
                        }

                        if let Err(e) = tun_tx.send(data).await {
                            return Err(anyhow::anyhow!("Failed to send to transport: {}", e));
                        }
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!("Error reading from TUN: {}", e));
                    }
                }
            }
        }
    }
}
