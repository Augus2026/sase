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

pub struct TcpTransport {
    stream: Arc<tokio::sync::Mutex<Option<TcpStream>>>,
    remote_addr: Arc<tokio::sync::Mutex<Option<SocketAddr>>>,
    read_buffer: Arc<tokio::sync::Mutex<Vec<u8>>>,
}

impl TcpTransport {
    pub async fn connect(addr: SocketAddr) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        info!("TCP connection established to {}", addr);

        let transport = Self {
            stream: Arc::new(tokio::sync::Mutex::new(Some(stream))),
            remote_addr: Arc::new(tokio::sync::Mutex::new(Some(addr))),
            read_buffer: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        };

        Ok(transport)
    }

    pub async fn accept(listener: &TcpListener) -> Result<Self> {
        let (stream, addr) = listener.accept().await?;
        info!("TCP connection accepted from {}", addr);

        let transport = Self {
            stream: Arc::new(tokio::sync::Mutex::new(Some(stream))),
            remote_addr: Arc::new(tokio::sync::Mutex::new(Some(addr))),
            read_buffer: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        };

        Ok(transport)
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
