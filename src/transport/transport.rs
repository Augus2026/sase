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
use tokio_tungstenite::{accept_async_with_config, WebSocketStream, MaybeTlsStream};
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;
use tokio_native_tls::TlsAcceptor;
use tokio_native_tls::TlsConnector;
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
    const DEFAULT_CERT_PATH: &'static str = "certs/server-cert.pem";
    const DEFAULT_KEY_PATH: &'static str = "certs/server-key.pem";
    const DEFAULT_CA_CERT_PATH: &'static str = "certs/ca-cert.pem";

    pub fn create_default_tls_acceptor() -> io::Result<TlsAcceptor> {
        Self::create_tls_acceptor(&Self::DEFAULT_CERT_PATH, &Self::DEFAULT_KEY_PATH)
    }

    pub fn create_tls_acceptor(cert_path: &str, key_path: &str) -> io::Result<TlsAcceptor> {
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

        let identity = Identity::from_pkcs8(cert_pem.as_bytes(), key_pem.as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to create identity: {}", e)))?;

        let acceptor = native_tls::TlsAcceptor::builder(identity)
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to create TLS acceptor: {}", e)))?;

        Ok(TlsAcceptor::from(acceptor))
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
        let use_tls = tls_acceptor.is_some();

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

    fn parse_url(url: &str) -> io::Result<(String, u16, bool)> {
        let parsed_url = url::Url::parse(url)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Failed to parse URL: {}", e)))?;

        let host = parsed_url.host_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Missing host in URL"))?
            .to_string();

        let port = parsed_url.port_or_known_default()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Missing port in URL"))?;

        let use_tls = parsed_url.scheme() == "wss";

        Ok((host, port, use_tls))
    }

    async fn establish_tcp_connection(host: &str, port: u16) -> io::Result<TcpStream> {
        TcpStream::connect((host, port))
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, format!("Failed to connect to {}: {}", host, e)))
    }

    async fn wrap_with_tls(tcp_stream: TcpStream, host: &str, ca_cert_path: &str) -> io::Result<MaybeTlsStream<TcpStream>> {
        log::info!("Establishing TLS connection to {} (with root certificate verification)", host);

        let mut builder = native_tls::TlsConnector::builder();
        if Path::new(ca_cert_path).exists() {
            let cert_pem = fs::read_to_string(ca_cert_path)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to read root CA certificate: {}", e)))?;
            let certificate = native_tls::Certificate::from_pem(cert_pem.as_bytes())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to parse root CA certificate: {}", e)))?;
            builder.add_root_certificate(certificate);
        }

        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);

        let tls_connector = builder.build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to build TLS connector: {}", e)))?;

        let tokio_tls_connector = TlsConnector::from(tls_connector);
        let tls_stream = tokio_tls_connector.connect(host, tcp_stream)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, format!("TLS handshake failed: {}", e)))?;

        Ok(MaybeTlsStream::NativeTls(tls_stream))
    }

    async fn perform_websocket_handshake(url: &str, stream: MaybeTlsStream<TcpStream>) -> io::Result<WebSocketStream<MaybeTlsStream<TcpStream>>> {
        let request = tokio_tungstenite::tungstenite::handshake::client::Request::from(
            tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(url)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Failed to create request: {}", e)))?
        );

        tokio_tungstenite::client_async_with_config(request, stream, None)
            .await
            .map(|(ws, _response)| ws)
            .map_err(|e| {
                log::error!("WebSocket handshake failed: {}", e);
                io::Error::new(io::ErrorKind::ConnectionRefused, format!("WebSocket handshake failed: {}", e))
            })
    }

    pub async fn connect(url: &str) -> io::Result<Self> {
        log::info!("Connecting to WebSocket server at {}", url);

        let (host, port, use_tls) = Self::parse_url(url)?;

        let tcp_stream = Self::establish_tcp_connection(&host, port).await?;

        let stream = if use_tls {
            Self::wrap_with_tls(tcp_stream, &host, &Self::DEFAULT_CA_CERT_PATH).await?
        } else {
            MaybeTlsStream::Plain(tcp_stream)
        };

        let ws_stream = Self::perform_websocket_handshake(url, stream).await?;

        let server_addr = format!("{}:{}", host, port)
            .parse()
            .unwrap_or_else(|_| "127.0.0.1:80".parse().unwrap());

        log::info!("Connected to WebSocket server at {}", url);

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
                            match bincode::deserialize::<Message>(&bytes) {
                                Ok(msg) => return Some(Ok((msg, self.peer_addr))),
                                Err(e) => return Some(Err(io::Error::new(io::ErrorKind::InvalidData, e))),
                            }
                        }
                        WsMessage::Close(_) => return None,
                        WsMessage::Ping(data) => {
                            if let Err(e) = self.ws_stream.send(WsMessage::Pong(data)).await {
                                return Some(Err(io::Error::new(io::ErrorKind::BrokenPipe, e)));
                            }
                            continue;
                        }
                        WsMessage::Pong(_) => {
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
