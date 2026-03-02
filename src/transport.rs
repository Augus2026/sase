use crate::common::{
    VpnPacket,
    TUN_MTU
};
use anyhow::Result;
use log::{debug, info, warn, error};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::net::UdpSocket as StdUdpSocket;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UdpSocket, TcpListener, TcpStream};

#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize>;

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;
}
