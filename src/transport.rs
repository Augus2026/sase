use anyhow::Result;
use std::net::SocketAddr;

#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize>;

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;
}
