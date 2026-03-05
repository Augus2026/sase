//! Transport abstraction for TCP and UDP communication

use crate::codec::{Message, ByteCodec};
use std::io;
use std::net::SocketAddr;
use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::net::UdpSocket;
use tokio_util::codec::Framed;
use tokio_util::udp::UdpFramed;

/// Transport trait abstracting send and receive operations
#[allow(async_fn_in_trait)]
pub trait TransportTrait {
    /// Error type for this transport
    type Error;

    /// Send a message to transport
    async fn send(&mut self, msg: Message, addr: SocketAddr) -> Result<(), Self::Error>;

    /// Receive the next message from transport
    async fn next(&mut self) -> Option<Result<(Message, SocketAddr), Self::Error>>;
}

/// TCP transport implementation
pub struct TcpTransport {
    framed: Framed<TcpStream, ByteCodec>,
    peer_addr: SocketAddr,
}

impl TcpTransport {
    /// Create a new TCP transport with custom codec
    pub fn new(stream: TcpStream) -> io::Result<Self> {
        let peer_addr = stream.peer_addr()?;
        Ok(Self {
            framed: Framed::new(stream, ByteCodec::new()),
            peer_addr,
        })
    }

    /// Connect to a TCP server
    pub async fn connect(addr: &str) -> io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        Self::new(stream)
    }

    /// Accept a connection from a TCP listener
    pub async fn accept(listener: &TcpListener) -> io::Result<Self> {
        let (stream, _) = listener.accept().await?;
        Self::new(stream)
    }

    /// Bind to a TCP address for server
    pub async fn bind(addr: &str) -> io::Result<TcpListener> {
        TcpListener::bind(addr).await
    }

    /// Get the peer address
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    // Get the local address
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.framed.get_ref().local_addr()
    }
}

impl TransportTrait for TcpTransport {
    type Error = io::Error;

    async fn send(&mut self, msg: Message, _addr: SocketAddr) -> Result<(), Self::Error> {
        self.framed.send(msg).await
    }

    async fn next(&mut self) -> Option<Result<(Message, SocketAddr), Self::Error>> {
        let result = self.framed.next().await;
        result.map(|r| r.map(|msg| (msg, self.peer_addr)))
    }
}

/// UDP transport implementation
pub struct UdpTransport {
    framed: UdpFramed<ByteCodec>,
}

impl UdpTransport {
    /// Create a new UDP transport
    pub fn new(socket: UdpSocket) -> Self {
        Self {
            framed: UdpFramed::new(socket, ByteCodec::new()),
        }
    }

    /// Bind to a UDP address
    pub async fn bind(addr: &str) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self::new(socket))
    }

    /// Connect to a UDP remote address
    pub async fn connect(addr: &str) -> io::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(addr).await?;
        Ok(Self::new(socket))
    }

    // Get the local address
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.framed.get_ref().local_addr()
    }
}

impl TransportTrait for UdpTransport {
    type Error = io::Error;

    async fn send(&mut self, msg: Message, addr: SocketAddr) -> Result<(), Self::Error> {
        self.framed.send((msg, addr)).await
    }

    async fn next(&mut self) -> Option<Result<(Message, SocketAddr), Self::Error>> {
        self.framed.next().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_tcp() {
        let listener = TcpTransport::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        println!("TCP Server: Listening on {}", server_addr);

        tokio::spawn(async move {
            let mut server = TcpTransport::accept(&listener).await.unwrap();
            println!("TCP Server: Client connected from {}", server.peer_addr());

            if let Some(Ok((msg, peer_addr))) = server.next().await {
                println!("TCP Server: Received from {}", peer_addr);
                println!("  Payload: {:?}", msg.payload_as_string());

                let ack = Message::ack(b"Server ACK".to_vec());
                server.send(ack, peer_addr).await.unwrap();
                println!("TCP Server: Sent ACK to {}", peer_addr);
            }
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let mut client = TcpTransport::connect(server_addr.to_string().as_str()).await.unwrap();
        println!("TCP Client: Connected to {}", client.peer_addr());

        let msg = Message::text("Hello from TCP client");
        client.send(msg, client.peer_addr()).await.unwrap();
        println!("TCP Client: Sent message");

        if let Some(Ok((ack, _))) = client.next().await {
            println!("TCP Client: Received ACK: {:?}", ack.payload_as_string());
            assert_eq!(ack.message_type, 4); // MessageType::Ack
            assert_eq!(ack.payload_as_string(), Some("Server ACK".to_string()));
        }
    }

    #[tokio::test]
    async fn test_udp() {
        let mut server = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        println!("UDP Server: Listening on {}", server_addr);

        tokio::spawn(async move {
            if let Some(Ok((msg, from_addr))) = server.next().await {
                println!("UDP Server: Received from {}", from_addr);
                println!("  Payload: {:?}", msg.payload_as_string());

                let ack = Message::ack(b"UDP ACK".to_vec());
                server.send(ack, from_addr).await.unwrap();
                println!("UDP Server: Sent ACK to {}", from_addr);
            }
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let mut client = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        println!("UDP Client: Bound to {}", client_addr);

        let msg = Message::text("Hello from UDP client");
        client.send(msg, server_addr).await.unwrap();
        println!("UDP Client: Sent message");

        if let Some(Ok((ack, from_addr))) = client.next().await {
            println!("UDP Client: Received ACK from {}: {:?}", from_addr, ack.payload_as_string());
            assert_eq!(from_addr, server_addr);
            assert_eq!(ack.payload_as_string(), Some("UDP ACK".to_string()));
        }
    }
}
