use crate::codec::{Message, ByteCodec};
use std::io;
use std::net::SocketAddr;
use std::fs;
use std::path::Path;
use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::net::UdpSocket;
use tokio_util::codec::Framed;
use tokio_util::udp::UdpFramed;
use socket2::Socket;
use tokio_tungstenite::{accept_async_with_config, connect_async, WebSocketStream, MaybeTlsStream};
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;
use tokio_native_tls::TlsAcceptor;
use native_tls::Identity;
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

        const BUFFER_SIZE: usize = 8 * 1024 * 1024;
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
        const BUFFER_SIZE: usize = 8 * 1024 * 1024;
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

pub struct WsTransport {
    ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    peer_addr: SocketAddr,
}

impl WsTransport {
    // Default paths for TLS certificates
    const DEFAULT_CERT_PATH: &'static str = "certs/server.crt";
    const DEFAULT_KEY_PATH: &'static str = "certs/server.key";
    const DEFAULT_PKCS12_PATH: &'static str = "certs/server.p12";

    /// Create a TLS acceptor from certificate and key files
    pub fn create_tls_acceptor_from_pem(cert_path: &str, key_path: &str) -> io::Result<TlsAcceptor> {
        let cert_path = if Path::new(cert_path).exists() {
            cert_path
        } else {
            log::warn!("Certificate file not found at {}, trying default path: {}", cert_path, Self::DEFAULT_CERT_PATH);
            Self::DEFAULT_CERT_PATH
        };

        let key_path = if Path::new(key_path).exists() {
            key_path
        } else {
            log::warn!("Key file not found at {}, trying default path: {}", key_path, Self::DEFAULT_KEY_PATH);
            Self::DEFAULT_KEY_PATH
        };

        // Check if default files exist
        if !Path::new(cert_path).exists() || !Path::new(key_path).exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Certificate or key file not found. Looking for {} and {}", cert_path, key_path)
            ));
        }

        let cert_pem = fs::read_to_string(cert_path)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to read certificate: {}", e)))?;

        let key_pem = fs::read_to_string(key_path)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to read key: {}", e)))?;

        // Create identity from certificate and key
        let identity = Identity::from_pkcs8(cert_pem.as_bytes(), key_pem.as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to create identity: {}", e)))?;

        // Create acceptor
        let acceptor = native_tls::TlsAcceptor::builder(identity)
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to create TLS acceptor: {}", e)))?;

        Ok(TlsAcceptor::from(acceptor))
    }

    /// Create a TLS acceptor from PKCS12 file
    pub fn create_tls_acceptor_from_pkcs12(pkcs12_path: &str, password: &str) -> io::Result<TlsAcceptor> {
        let pkcs12_path = if Path::new(pkcs12_path).exists() {
            pkcs12_path
        } else {
            log::warn!("PKCS12 file not found at {}, trying default path: {}", pkcs12_path, Self::DEFAULT_PKCS12_PATH);
            Self::DEFAULT_PKCS12_PATH
        };

        if !Path::new(pkcs12_path).exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("PKCS12 file not found: {}", pkcs12_path)
            ));
        }

        let pkcs12 = fs::read(pkcs12_path)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to read PKCS12 file: {}", e)))?;

        let identity = Identity::from_pkcs12(&pkcs12, password)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to parse PKCS12: {}", e)))?;

        let acceptor = native_tls::TlsAcceptor::new(identity)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to create TLS acceptor: {}", e)))?;

        Ok(TlsAcceptor::from(acceptor))
    }

    /// Try to create TLS acceptor from default certificate paths
    pub fn try_create_default_tls_acceptor() -> io::Result<Option<TlsAcceptor>> {
        // Try PEM files first
        match Self::create_tls_acceptor_from_pem(Self::DEFAULT_CERT_PATH, Self::DEFAULT_KEY_PATH) {
            Ok(acceptor) => {
                log::info!("Using TLS certificates from {} and {}", Self::DEFAULT_CERT_PATH, Self::DEFAULT_KEY_PATH);
                return Ok(Some(acceptor));
            }
            Err(e) => {
                log::debug!("Failed to load PEM certificates: {}", e);
            }
        }

        // Try PKCS12 file
        if Path::new(Self::DEFAULT_PKCS12_PATH).exists() {
            match Self::create_tls_acceptor_from_pkcs12(Self::DEFAULT_PKCS12_PATH, "") {
                Ok(acceptor) => {
                    log::info!("Using TLS certificate from {}", Self::DEFAULT_PKCS12_PATH);
                    return Ok(Some(acceptor));
                }
                Err(e) => {
                    log::debug!("Failed to load PKCS12 certificate: {}", e);
                }
            }
        }

        log::info!("No TLS certificates found, using plain TCP");
        Ok(None)
    }
    pub async fn new(stream: TcpStream) -> io::Result<Self> {
        let peer_addr = stream.peer_addr()?;
        let ws_stream = WebSocketStream::from_raw_socket(
            MaybeTlsStream::Plain(stream),
            tokio_tungstenite::tungstenite::protocol::Role::Server,
            None
        ).await;
        Ok(Self { ws_stream, peer_addr })
    }

    pub async fn accept(listener: &TcpListener, tls_acceptor: Option<TlsAcceptor>) -> io::Result<Self> {
        let (stream, addr) = listener.accept().await?;
        let peer_addr = addr;

        if tls_acceptor.is_some() {
            log::info!("Attempting WSS (WebSocket Secure) connection from {}", addr);
        } else {
            log::info!("Attempting WebSocket connection from {}", addr);
        }

        // Check if TLS is enabled
        let use_tls = tls_acceptor.is_some();

        // Perform TLS handshake if acceptor is provided
        let tls_stream = if let Some(ref acceptor) = tls_acceptor {
            match acceptor.accept(stream).await {
                Ok(tls) => MaybeTlsStream::NativeTls(tls),
                Err(e) => {
                    log::error!("TLS handshake failed from {}: {}", addr, e);
                    return Err(io::Error::new(io::ErrorKind::ConnectionRefused, e));
                }
            }
        } else {
            MaybeTlsStream::Plain(stream)
        };

        // Perform WebSocket handshake
        let ws_stream = match accept_async_with_config(tls_stream, None).await {
            Ok(ws) => ws,
            Err(e) => {
                log::error!("WebSocket handshake failed from {}: {}", addr, e);
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, e));
            }
        };

        if use_tls {
            log::info!("WSS connection established from {}", addr);
        } else {
            log::info!("WebSocket connection established from {}", addr);
        }

        Ok(Self { ws_stream, peer_addr })
    }

    pub async fn bind(addr: &str) -> io::Result<TcpListener> {
        TcpListener::bind(addr).await
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
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

        Ok(Self { ws_stream, peer_addr: server_addr })
    }

    pub fn server_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

impl TransportTrait for WsTransport {
    type Error = io::Error;

    async fn send(&mut self, msg: Message, _addr: SocketAddr) -> Result<(), Self::Error> {
        let bytes = bincode::serialize(&msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let ws_msg = WsMessage::Binary(bytes);
        self.ws_stream.send(ws_msg).await.map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))
    }

    async fn next(&mut self) -> Option<Result<(Message, SocketAddr), Self::Error>> {
        loop {
            match self.ws_stream.next().await {
                Some(Ok(ws_msg)) => {
                    match ws_msg {
                        WsMessage::Binary(bytes) => {
                            // Deserialize Message from bytes
                            match bincode::deserialize::<Message>(&bytes) {
                                Ok(msg) => return Some(Ok((msg, self.peer_addr))),
                                Err(e) => return Some(Err(io::Error::new(io::ErrorKind::InvalidData, e))),
                            }
                        }
                        WsMessage::Close(_) => return None,
                        WsMessage::Ping(data) => {
                            // Respond to ping with pong and continue
                            if let Err(e) = self.ws_stream.send(WsMessage::Pong(data)).await {
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
