use crate::codec::{Message, ByteCodec};
use std::io;
use std::net::SocketAddr;
use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::net::UdpSocket;
use tokio_util::codec::Framed;
use tokio_util::udp::UdpFramed;
use socket2::Socket;
use tokio_tungstenite::{accept_async, connect_async, WebSocketStream, MaybeTlsStream};
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;
use bincode;

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
pub enum WsTransport {
    Client {
        ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
        peer_addr: SocketAddr,
    },
    Server {
        ws_stream: WebSocketStream<TcpStream>,
        peer_addr: SocketAddr,
    },
}

impl WsTransport {
    pub async fn new(stream: TcpStream) -> io::Result<Self> {
        let peer_addr = stream.peer_addr()?;
        let ws_stream = WebSocketStream::from_raw_socket(
            MaybeTlsStream::Plain(stream),
            tokio_tungstenite::tungstenite::protocol::Role::Server,
            None
        ).await;
        Ok(Self::Client { ws_stream, peer_addr })
    }

    pub async fn accept(listener: &TcpListener) -> io::Result<Self> {
        let (stream, addr) = listener.accept().await?;
        let peer_addr = addr;
        log::info!("Attempting WebSocket connection from {}", addr);

        // Perform WebSocket handshake
        let ws_stream = match accept_async(stream).await {
            Ok(ws) => ws,
            Err(e) => {
                log::error!("WebSocket handshake failed from {}: {}", addr, e);
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, e));
            }
        };

        log::info!("WebSocket connection established from {}", addr);

        Ok(Self::Server { ws_stream, peer_addr })
    }

    pub async fn bind(addr: &str) -> io::Result<TcpListener> {
        TcpListener::bind(addr).await
    }

    pub fn peer_addr(&self) -> SocketAddr {
        match self {
            Self::Client { peer_addr, .. } => *peer_addr,
            Self::Server { peer_addr, .. } => *peer_addr,
        }
    }

    pub async fn connect(url: &str) -> io::Result<Self> {
        log::info!("Connecting to WebSocket server at {}", url);

        let (ws_stream, _response) = match connect_async(url).await {
            Ok(conn) => conn,
            Err(e) => {
                log::error!("Failed to connect to WebSocket server {}: {}", url, e);
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, e));
            }
        };
        log::info!("Connected to WebSocket server");

        // Extract peer address from URL
        let server_addr = url::Url::parse(url)
            .ok()
            .and_then(|parsed_url: url::Url| {
                let host = parsed_url.host_str().unwrap_or("localhost");
                let port = parsed_url.port_or_known_default().unwrap_or(80);
                format!("{}:{}", host, port).parse().ok()
            })
            .unwrap_or_else(|| "127.0.0.1:80".parse().unwrap());

        Ok(Self::Client { ws_stream, peer_addr: server_addr })
    }

    pub fn server_addr(&self) -> SocketAddr {
        match self {
            Self::Client { peer_addr, .. } => *peer_addr,
            Self::Server { peer_addr, .. } => *peer_addr,
        }
    }
}

impl TransportTrait for WsTransport {
    type Error = io::Error;

    async fn send(&mut self, msg: Message, _addr: SocketAddr) -> Result<(), Self::Error> {
        // Serialize Message to bytes and send as WebSocket binary message
        let bytes = bincode::serialize(&msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let ws_msg = WsMessage::Binary(bytes);

        match self {
            Self::Client { ws_stream, .. } => {
                ws_stream.send(ws_msg).await
                    .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))
            }
            Self::Server { ws_stream, .. } => {
                ws_stream.send(ws_msg).await
                    .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))
            }
        }
    }

    async fn next(&mut self) -> Option<Result<(Message, SocketAddr), Self::Error>> {
        loop {
            match self {
                Self::Client { ws_stream, peer_addr } => {
                    match ws_stream.next().await {
                        Some(Ok(ws_msg)) => {
                            match ws_msg {
                                WsMessage::Binary(bytes) => {
                                    // Deserialize Message from bytes
                                    match bincode::deserialize::<Message>(&bytes) {
                                        Ok(msg) => return Some(Ok((msg, *peer_addr))),
                                        Err(e) => return Some(Err(io::Error::new(io::ErrorKind::InvalidData, e))),
                                    }
                                }
                                WsMessage::Close(_) => return None,
                                WsMessage::Ping(data) => {
                                    // Respond to ping with pong and continue
                                    if let Err(e) = ws_stream.send(WsMessage::Pong(data)).await {
                                        return Some(Err(io::Error::new(io::ErrorKind::BrokenPipe, e)));
                                    }
                                    // Continue to next message
                                    continue;
                                }
                                WsMessage::Pong(_) => {
                                    // Ignore pongs, continue to next message
                                    continue;
                                }
                                WsMessage::Text(_) | WsMessage::Frame(_) => {
                                    return Some(Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported WebSocket message type")));
                                }
                            }
                        }
                        Some(Err(e)) => return Some(Err(io::Error::new(io::ErrorKind::BrokenPipe, e))),
                        None => return None,
                    }
                }
                Self::Server { ws_stream, peer_addr } => {
                    match ws_stream.next().await {
                        Some(Ok(ws_msg)) => {
                            match ws_msg {
                                WsMessage::Binary(bytes) => {
                                    // Deserialize Message from bytes
                                    match bincode::deserialize::<Message>(&bytes) {
                                        Ok(msg) => return Some(Ok((msg, *peer_addr))),
                                        Err(e) => return Some(Err(io::Error::new(io::ErrorKind::InvalidData, e))),
                                    }
                                }
                                WsMessage::Close(_) => return None,
                                WsMessage::Ping(data) => {
                                    // Respond to ping with pong and continue
                                    if let Err(e) = ws_stream.send(WsMessage::Pong(data)).await {
                                        return Some(Err(io::Error::new(io::ErrorKind::BrokenPipe, e)));
                                    }
                                    // Continue to next message
                                    continue;
                                }
                                WsMessage::Pong(_) => {
                                    // Ignore pongs, continue to next message
                                    continue;
                                }
                                WsMessage::Text(_) | WsMessage::Frame(_) => {
                                    return Some(Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported WebSocket message type")));
                                }
                            }
                        }
                        Some(Err(e)) => return Some(Err(io::Error::new(io::ErrorKind::BrokenPipe, e))),
                        None => return None,
                    }
                }
            }
        }
    }
}
