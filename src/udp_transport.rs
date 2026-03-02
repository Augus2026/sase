use crate::common::{
    VpnPacket,
    TUN_MTU
};
use crate::transport::{
    Transport
};
use anyhow::Result;
use log::{debug, info, warn, error};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::net::UdpSocket as StdUdpSocket;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UdpSocket, TcpListener, TcpStream};

pub const DEFAULT_RECV_BUFFER_SIZE: usize = 4 * 1024 * 1024;
pub const DEFAULT_SEND_BUFFER_SIZE: usize = 4 * 1024 * 1024;

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

pub struct UdpTransport {
    socket: Arc<UdpSocket>,
}

impl UdpTransport {
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        Self { socket }
    }

    pub fn from_std(std_socket: StdUdpSocket) -> Result<Self> {
        let recv_buffer_size = DEFAULT_RECV_BUFFER_SIZE;
        let send_buffer_size = DEFAULT_SEND_BUFFER_SIZE;
        let socket = configure_udp_socket(std_socket, recv_buffer_size, send_buffer_size)?;
        Ok(Self { socket })
    }
}

#[async_trait::async_trait]
impl Transport for UdpTransport {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize> {
        self.socket.send_to(buf, addr).await.map_err(Into::into)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf).await.map_err(Into::into)
    }
}
