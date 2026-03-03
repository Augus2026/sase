use crate::common::{TUN_MTU, VpnPacket};
use crate::transport::Transport;
use anyhow::Result;
use log::{info, trace};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct TcpTransport {
    stream: Arc<tokio::sync::Mutex<Option<TcpStream>>>,
    // Cache remote address to avoid frequent locking
    cached_remote_addr: SocketAddr,
    read_buffer: Arc<tokio::sync::Mutex<Vec<u8>>>,
}

impl TcpTransport {
    pub async fn connect(addr: SocketAddr) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;

        // Disable Nagle's algorithm to reduce latency for small packets
        stream.set_nodelay(true)?;

        info!("TCP connection established to {}", addr);

        let transport = Self {
            stream: Arc::new(tokio::sync::Mutex::new(Some(stream))),
            cached_remote_addr: addr,
            read_buffer: Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(8192))),
        };

        Ok(transport)
    }

    pub fn from_stream(stream: TcpStream, remote_addr: SocketAddr) -> Result<Self> {
        let transport = Self {
            stream: Arc::new(tokio::sync::Mutex::new(Some(stream))),
            cached_remote_addr: remote_addr,
            read_buffer: Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(8192))),
        };

        Ok(transport)
    }

    // Helper: Try to read a complete frame from buffer without holding stream lock
    fn try_read_from_buffer(&self, buffer: &mut Vec<u8>) -> Result<Option<Vec<u8>>> {
        if buffer.len() < 4 {
            return Ok(None);
        }

        let msg_len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;

        // Check if message length is reasonable
        if msg_len > TUN_MTU + VpnPacket::HEADER_SIZE {
            anyhow::bail!("Message too large: {}", msg_len);
        }

        // Check if we have the complete message
        if buffer.len() < 4 + msg_len {
            return Ok(None);
        }

        // Extract the message (without length prefix)
        let message = buffer[4..4 + msg_len].to_vec();

        // Remove the consumed data from buffer
        buffer.drain(0..4 + msg_len);

        Ok(Some(message))
    }

    // Helper: Copy message to output buffer
    fn copy_to_buffer(&self, message: &[u8], buf: &mut [u8]) -> usize {
        let len = std::cmp::min(message.len(), buf.len());
        if len > 0 {
            buf[..len].copy_from_slice(&message[..len]);
        }
        len
    }

    // Helper: Read data from stream into buffer
    async fn read_stream_data(&self, buffer: &mut Vec<u8>) -> Result<()> {
        let mut stream_guard = self.stream.lock().await;
        let stream = stream_guard.as_mut().ok_or_else(|| anyhow::anyhow!("No active TCP connection"))?;

        // Pre-allocate space to minimize reallocations
        if buffer.capacity() < buffer.len() + 4096 {
            buffer.reserve(4096);
        }

        let mut temp_buf = [0u8; 4096];

        // Read data with timeout to prevent indefinite blocking
        match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            stream.read(&mut temp_buf)
        ).await {
            Ok(Ok(n)) => {
                if n == 0 {
                    anyhow::bail!("Connection closed");
                }
                buffer.extend_from_slice(&temp_buf[..n]);
                trace!("Read {} bytes from stream, buffer size: {}", n, buffer.len());
            }
            Ok(Err(e)) => {
                anyhow::bail!("Stream read error: {}", e);
            }
            Err(_) => {
                anyhow::bail!("Stream read timeout");
            }
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
        let length_bytes = length.to_be_bytes();

        // Write length prefix first
        stream.write_all(&length_bytes).await?;

        // Then write the data directly without extra allocation
        if !buf.is_empty() {
            stream.write_all(buf).await?;
        }

        // Flush immediately to reduce latency
        stream.flush().await?;

        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        trace!("TcpTransport::recv_from called");

        // Use cached remote address to avoid locking
        let remote_addr = self.cached_remote_addr;

        // Try to read a complete frame from the buffer
        let message = {
            let mut buffer = self.read_buffer.lock().await;

            // Try to read from buffer first without holding stream lock
            if let Some(msg) = self.try_read_from_buffer(&mut buffer)? {
                return Ok((self.copy_to_buffer(&msg, buf), remote_addr));
            }

            // Need to read from stream
            // Now read data into buffer
            self.read_stream_data(&mut buffer).await?;

            // Try again to read from buffer
            match self.try_read_from_buffer(&mut buffer)? {
                Some(msg) => msg,
                None => {
                    // If we still don't have a complete frame, read more
                    self.read_stream_data(&mut buffer).await?;
                    self.try_read_from_buffer(&mut buffer)?
                        .ok_or_else(|| anyhow::anyhow!("Failed to read complete frame"))?
                }
            }
        };

        // Copy to output buffer
        let len = self.copy_to_buffer(&message, buf);

        Ok((len, remote_addr))
    }
}
