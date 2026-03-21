use crate::codec::{Message, ByteCodec};
use std::io;
use std::net::SocketAddr;
use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::net::UdpSocket;
use tokio_util::codec::Framed;
use tokio_util::udp::UdpFramed;
use socket2::Socket;
use tokio_tungstenite::connect_async;

#[allow(async_fn_in_trait)]
pub trait TransportTrait {
    type Error;

    async fn send(&mut self, msg: Message, addr: SocketAddr) -> Result<(), Self::Error>;
    async fn next(&mut self) -> Option<Result<(Message, SocketAddr), Self::Error>>;
}

pub struct TcpTransport {
    framed: Framed<TcpStream, ByteCodec>,
    peer_addr: SocketAddr,
}

impl TcpTransport {
    pub fn new(stream: TcpStream) -> io::Result<Self> {
        let peer_addr = stream.peer_addr()?;

        // Set 8MB buffer sizes using socket2
        const BUFFER_SIZE: usize = 8 * 1024 * 1024; // 8MB
        let socket = Socket::from(stream.into_std()?);
        socket.set_send_buffer_size(BUFFER_SIZE)?;
        socket.set_recv_buffer_size(BUFFER_SIZE)?;
        let stream = TcpStream::from_std(socket.into())?;

        Ok(Self {
            framed: Framed::new(stream, ByteCodec::new()),
            peer_addr,
        })
    }

    pub async fn connect(addr: &str) -> io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        Self::new(stream)
    }

    pub async fn accept(listener: &TcpListener) -> io::Result<Self> {
        let (stream, _) = listener.accept().await?;
        Self::new(stream)
    }

    pub async fn bind(addr: &str) -> io::Result<TcpListener> {
        TcpListener::bind(addr).await
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
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

pub struct UdpTransport {
    framed: UdpFramed<ByteCodec>,
}

impl UdpTransport {
    pub fn new(socket: UdpSocket) -> Self {
        // Set 8MB buffer sizes using socket2
        const BUFFER_SIZE: usize = 8 * 1024 * 1024; // 8MB
        let std_socket = socket.into_std().expect("Failed to convert to std socket");
        let socket2_socket = Socket::from(std_socket);
        let _ = socket2_socket.set_send_buffer_size(BUFFER_SIZE);
        let _ = socket2_socket.set_recv_buffer_size(BUFFER_SIZE);
        let std_socket = socket2_socket.into();
        let socket = UdpSocket::from_std(std_socket).expect("Failed to convert back to UdpSocket");

        Self {
            framed: UdpFramed::new(socket, ByteCodec::new()),
        }
    }

    pub async fn bind(addr: &str) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self::new(socket))
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

/// WebSocket transport - handles WebSocket connections
pub struct WsTransport {
    framed: Framed<TcpStream, ByteCodec>,
    peer_addr: SocketAddr,
}

impl WsTransport {
    pub fn new(stream: TcpStream) -> io::Result<Self> {
        let peer_addr = stream.peer_addr()?;
        Ok(Self {
            framed: Framed::new(stream, ByteCodec::new()),
            peer_addr,
        })
    }

    pub async fn accept(listener: &TcpListener) -> io::Result<Self> {
        let (stream, addr) = listener.accept().await?;
        let peer_addr = addr;
        log::info!("Attempting WebSocket connection from {}", addr);

        Ok(Self {
            framed: Framed::new(stream, ByteCodec::new()),
            peer_addr,
        })
    }

    pub async fn bind(addr: &str) -> io::Result<TcpListener> {
        TcpListener::bind(addr).await
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    pub async fn connect(url: &str) -> io::Result<Self> {
        log::info!("Connecting to WebSocket server at {}", url);

        let (_ws_stream, _) = match connect_async(url).await {
            Ok(conn) => conn,
            Err(e) => {
                log::error!("Failed to connect to WebSocket server {}: {}", url, e);
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, e));
            }
        };
        log::info!("Connected to WebSocket server");

        let parsed_url = url::Url::parse(url).unwrap_or_else(|_| url::Url::parse("ws://localhost:8080").unwrap());
        let host = parsed_url.host_str().unwrap_or("localhost");
        let port = parsed_url.port_or_known_default().unwrap_or(8080);
        let server_addr = format!("{}:{}", host, port).parse().unwrap_or_else(|_| "127.0.0.1:8080".parse().unwrap());

        let stream = TcpStream::connect(server_addr).await?;

        Ok(Self {
            framed: Framed::new(stream, ByteCodec::new()),
            peer_addr: server_addr,
        })
    }

    pub fn server_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

impl TransportTrait for WsTransport {
    type Error = io::Error;

    async fn send(&mut self, msg: Message, _addr: SocketAddr) -> Result<(), Self::Error> {
        self.framed.send(msg).await
    }

    async fn next(&mut self) -> Option<Result<(Message, SocketAddr), Self::Error>> {
        let result = self.framed.next().await;
        result.map(|r| r.map(|msg| (msg, self.peer_addr)))
    }
}
