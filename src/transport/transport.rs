use crate::codec::{ByteCodec, Message};
use futures::{SinkExt, StreamExt};
use native_tls::Identity;
use prost::Message as _;
use socket2::Socket;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use tokio::net::UdpSocket;
use tokio::net::{TcpListener, TcpStream};
use tokio_native_tls::TlsAcceptor;
use tokio_native_tls::TlsConnector;
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;
use tokio_tungstenite::{accept_async_with_config, MaybeTlsStream, WebSocketStream};
use tokio_util::codec::Framed;
use tokio_util::udp::UdpFramed;

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
    pub fn create_tls_acceptor(cert_path: &str, key_path: &str) -> io::Result<TlsAcceptor> {
        let resolve_path = |path: &str, default: &'static str| -> String {
            if Path::new(path).exists() {
                path.to_string()
            } else {
                default.to_string()
            }
        };

        let cert_path = resolve_path(cert_path, "certs/server-cert.pem");
        let key_path = resolve_path(key_path, "certs/server-key.pem");

        if !Path::new(&cert_path).exists() || !Path::new(&key_path).exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "Certificate or key file not found. Looking for {} and {}",
                    cert_path, key_path
                ),
            ));
        }

        let cert_bytes = fs::read(&cert_path).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to read certificate: {}", e),
            )
        })?;
        let key_bytes = fs::read(&key_path).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to read key: {}", e),
            )
        })?;
        let identity = Identity::from_pkcs8(&cert_bytes, &key_bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to create identity: {}", e),
            )
        })?;

        native_tls::TlsAcceptor::new(identity)
            .map(TlsAcceptor::from)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to create TLS acceptor: {}", e),
                )
            })
    }

    pub async fn accept(
        listener: &TcpListener,
        tls_acceptor: Option<TlsAcceptor>,
    ) -> io::Result<Self> {
        let (stream, addr) = listener.accept().await?;

        let tls_stream = if let Some(acceptor) = &tls_acceptor {
            acceptor
                .accept(stream)
                .await
                .map_err(|e| {
                    log::error!("TLS handshake failed from {}: {}", addr, e);
                    io::Error::new(io::ErrorKind::ConnectionRefused, e)
                })
                .map(MaybeTlsStream::NativeTls)?
        } else {
            MaybeTlsStream::Plain(stream)
        };

        let ws_stream = accept_async_with_config(tls_stream, None)
            .await
            .map_err(|e| {
                log::error!("WebSocket handshake failed from {}: {}", addr, e);
                io::Error::new(io::ErrorKind::ConnectionRefused, e)
            })?;

        log::info!(
            "{} connection established from {}",
            if tls_acceptor.is_some() {
                "WSS"
            } else {
                "WebSocket"
            },
            addr
        );

        Ok(Self {
            ws_stream,
            peer_addr: addr,
        })
    }

    pub async fn bind(addr: &str) -> io::Result<TcpListener> {
        TcpListener::bind(addr).await
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    fn parse_url(url: &str) -> io::Result<(String, u16, bool)> {
        let parsed_url = url::Url::parse(url).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Failed to parse URL: {}", e),
            )
        })?;

        let host = parsed_url
            .host_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Missing host in URL"))?
            .to_string();
        let port = parsed_url
            .port_or_known_default()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Missing port in URL"))?;
        let use_tls = parsed_url.scheme() == "wss";

        Ok((host, port, use_tls))
    }

    async fn wrap_with_tls(
        tcp_stream: TcpStream,
        host: &str,
        ca_cert_path: &str,
    ) -> io::Result<MaybeTlsStream<TcpStream>> {
        let mut builder = native_tls::TlsConnector::builder();

        if Path::new(ca_cert_path).exists() {
            let cert_pem = fs::read_to_string(ca_cert_path).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to read CA certificate: {}", e),
                )
            })?;
            let certificate =
                native_tls::Certificate::from_pem(cert_pem.as_bytes()).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Failed to parse CA certificate: {}", e),
                    )
                })?;
            builder.add_root_certificate(certificate);
        }

        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);

        let tls_connector = TlsConnector::from(builder.build().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to build TLS connector: {}", e),
            )
        })?);

        let tls_stream = tls_connector.connect(host, tcp_stream).await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("TLS handshake failed: {}", e),
            )
        })?;

        Ok(MaybeTlsStream::NativeTls(tls_stream))
    }

    pub async fn connect(url: &str, ca_cert_path: &str) -> io::Result<Self> {
        let (host, port, use_tls) = Self::parse_url(url)?;

        let tcp_stream = TcpStream::connect((&*host, port)).await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("Failed to connect to {}:{}", host, e),
            )
        })?;

        let stream = if use_tls {
            Self::wrap_with_tls(tcp_stream, &host, ca_cert_path).await?
        } else {
            MaybeTlsStream::Plain(tcp_stream)
        };

        let ws_stream = tokio_tungstenite::client_async_with_config(url, stream, None)
            .await
            .map(|(ws, _)| ws)
            .map_err(|e| {
                log::error!("WebSocket handshake failed: {}", e);
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("WebSocket handshake failed: {}", e),
                )
            })?;

        let server_addr = format!("{}:{}", host, port)
            .parse()
            .unwrap_or_else(|_| "127.0.0.1:80".parse().unwrap());

        log::info!("Connected to WebSocket server at {}", url);

        Ok(Self {
            ws_stream,
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
        let bytes = msg.encode_to_vec();
        let ws_msg = WsMessage::Binary(bytes);
        self.ws_stream
            .send(ws_msg)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))
    }

    async fn next(&mut self) -> Option<Result<(Message, SocketAddr), Self::Error>> {
        loop {
            match self.ws_stream.next().await {
                Some(Ok(WsMessage::Binary(bytes))) => {
                    return Message::decode(&bytes[..])
                        .map(|msg| Ok((msg, self.peer_addr)))
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
                        .ok();
                }
                Some(Ok(msg)) => {
                    log::warn!("Received unsupported WebSocket message type: {:?}", msg);
                    continue;
                }
                Some(Err(e)) => return Some(Err(io::Error::new(io::ErrorKind::BrokenPipe, e))),
                None => return None,
            }
        }
    }
}
