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

#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize>;

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;
}

pub struct UdpTransport {
    socket: Arc<UdpSocket>,
}

impl UdpTransport {
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        Self { socket }
    }

    pub fn from_std(std_socket: StdUdpSocket, recv_buffer_size: usize, send_buffer_size: usize) -> Result<Self> {
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

pub struct TcpTransport {
    listener: Option<Arc<TcpListener>>,
    stream: Arc<tokio::sync::Mutex<Option<TcpStream>>>,
    remote_addr: Arc<tokio::sync::Mutex<Option<SocketAddr>>>,
    read_buffer: Arc<tokio::sync::Mutex<Vec<u8>>>,
}

impl TcpTransport {
    pub fn new(listener: TcpListener) -> Self {
        Self {
            listener: Some(Arc::new(listener)),
            stream: Arc::new(tokio::sync::Mutex::new(None)),
            remote_addr: Arc::new(tokio::sync::Mutex::new(None)),
            read_buffer: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }

    pub async fn accept(&self) -> Result<TcpStream> {
        let listener = self.listener.as_ref().ok_or_else(|| anyhow::anyhow!("No listener available"))?;
        let (stream, addr) = listener.accept().await?;
        info!("TCP connection accepted from {}", addr);

        {
            let mut remote_addr = self.remote_addr.lock().await;
            *remote_addr = Some(addr);
        }

        {
            let mut stored_stream = self.stream.lock().await;
            *stored_stream = Some(stream);
        }

        {
            let mut buffer = self.read_buffer.lock().await;
            buffer.clear();
        }

        anyhow::bail!("TCP stream cannot be cloned, use the stored stream")
    }

    pub async fn connect(addr: SocketAddr) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;

        let transport = Self {
            listener: None,
            stream: Arc::new(tokio::sync::Mutex::new(Some(stream))),
            remote_addr: Arc::new(tokio::sync::Mutex::new(Some(addr))),
            read_buffer: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        };

        Ok(transport)
    }

    pub fn from_accepted_stream(stream: TcpStream, addr: SocketAddr) -> Self {
        info!("Creating TcpTransport from accepted stream, remote addr: {}", addr);
        Self {
            listener: None,
            stream: Arc::new(tokio::sync::Mutex::new(Some(stream))),
            remote_addr: Arc::new(tokio::sync::Mutex::new(Some(addr))),
            read_buffer: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }

    async fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> Result<()> {
        let mut pos = 0;
        while pos < buf.len() {
            let n = stream.read(&mut buf[pos..]).await?;
            if n == 0 {
                anyhow::bail!("Connection closed unexpectedly");
            }
            pos += n;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl Transport for TcpTransport {
    async fn send_to(&self, buf: &[u8], _addr: SocketAddr) -> Result<usize> {
        let mut stream_guard = self.stream.lock().await;
        let stream = stream_guard.as_mut().ok_or_else(|| anyhow::anyhow!("No active TCP connection"))?;

        // Add frame: [length (4 bytes, big-endian)] + [data]
        let length = buf.len() as u32;
        let mut frame = Vec::with_capacity(4 + buf.len());
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(buf);

        stream.write_all(&frame).await?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        debug!("TcpTransport::recv_from called");

        let remote_addr = {
            let remote_addr_guard = self.remote_addr.lock().await;
            match remote_addr_guard.as_ref() {
                Some(addr) => {
                    debug!("Remote address found: {}", addr);
                    *addr
                }
                None => {
                    error!("No remote address stored in TcpTransport");
                    anyhow::bail!("No remote address stored");
                }
            }
        };

        // Helper function to read one byte
        let read_byte = || async {
            let mut stream_guard = self.stream.lock().await;
            let stream = stream_guard.as_mut().ok_or_else(|| anyhow::anyhow!("No active TCP connection"))?;
            let mut byte_buf = [0u8; 1];
            let n = stream.read(&mut byte_buf).await?;
            if n == 0 {
                anyhow::bail!("Connection closed");
            }
            Ok::<u8, anyhow::Error>(byte_buf[0])
        };

        // Try to read a complete frame from the buffer
        let message = {
            let mut buffer = self.read_buffer.lock().await;

            // Read length prefix if not enough data
            while buffer.len() < 4 {
                let byte = read_byte().await?;
                buffer.push(byte);
            }

            // Parse message length
            let msg_len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;

            // Check if message length is reasonable
            if msg_len > TUN_MTU + VpnPacket::HEADER_SIZE {
                anyhow::bail!("Message too large: {}", msg_len);
            }

            // Read message body
            while buffer.len() < 4 + msg_len {
                let byte = read_byte().await?;
                buffer.push(byte);
            }

            // Extract the message (without length prefix)
            let message = buffer[4..4 + msg_len].to_vec();

            // Remove the consumed data from buffer
            buffer.drain(0..4 + msg_len);

            message
        };

        // Copy to output buffer
        let len = std::cmp::min(message.len(), buf.len());
        buf[..len].copy_from_slice(&message[..len]);

        Ok((len, remote_addr))
    }
}
