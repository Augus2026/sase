use std::net::{Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const SERVER_ADDR: &str = "127.0.0.1";
pub const SERVER_PORT: u16 = 12345;
pub const TUN_NAME: &str = "tun0";
pub const TUN_MTU: usize = 1500;

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub transport_type: String,
    pub server_addr: SocketAddr,
    pub ca_cert_path: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            transport_type: "udp".to_string(),
            server_addr: format!("{}:{}", SERVER_ADDR, SERVER_PORT).parse().unwrap(),
            ca_cert_path: "certs/ca-cert.pem".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub transport_type: String,
    pub bind_addr: SocketAddr,
    pub tun_name: String,
    pub tun_addr: Ipv4Addr,
    pub tun_netmask: Ipv4Addr,
    pub mtu: usize,
    pub cert_path: String,
    pub key_path: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            transport_type: "udp".to_string(),
            bind_addr: format!("{}:{}", SERVER_ADDR, SERVER_PORT).parse().unwrap(),
            tun_name: TUN_NAME.to_string(),
            tun_addr: Ipv4Addr::new(10, 0, 0, 1),
            tun_netmask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: TUN_MTU,
            cert_path: "certs/server-cert.pem".to_string(),
            key_path: "certs/server-key.pem".to_string(),
        }
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
