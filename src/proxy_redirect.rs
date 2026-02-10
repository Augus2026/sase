//! REDIRECT-based transparent proxy implementation
//!
//! This module implements transparent proxying using iptables REDIRECT target.
//! In this mode, TCP connections are redirected to a local proxy server that can
//! inspect and forward the traffic.
//!
//! Architecture:
//! TUN interface -> [iptables REDIRECT] -> Local Proxy Port -> Application -> Internet
//!
//! Pros:
//! - Full application-layer visibility and control
//! - Can inspect/modify traffic
//! - Connection logging and filtering
//! - True transparent proxy behavior
//!
//! Cons:
//! - Higher overhead (userspace forwarding)
//! - More complex setup
//! - Only handles TCP (UDP would need TPROXY)

use anyhow::Result;
use log::{info, error, debug};
use crate::common::ServerConfig;
use std::net::SocketAddr;
use tokio::net::TcpListener;

/// Start REDIRECT-based transparent proxy
///
/// This sets up iptables REDIRECT rules and starts a TCP proxy server
/// that handles redirected connections.
#[cfg(target_os = "linux")]
pub async fn start_redirect_proxy(config: &ServerConfig) -> Result<()> {
    let tun_if = &config.tun_name;
    let redirect_port = config.transparent_proxy.redirect_port;

    info!("[REDIRECT PROXY] Starting REDIRECT-based transparent proxy");
    info!("[REDIRECT PROXY] TUN interface: {}", tun_if);
    info!("[REDIRECT PROXY] Redirect port: {}", redirect_port);

    // Setup iptables REDIRECT rules
    setup_redirect_rules(tun_if, redirect_port).await?;

    // Start TCP proxy server
    start_tcp_proxy(redirect_port).await?;

    Ok(())
}

/// Get the original destination of a redirected connection using SO_ORIGINAL_DST
#[cfg(target_os = "linux")]
fn get_original_dst(socket: &tokio::net::TcpStream) -> Result<SocketAddr> {
    use std::os::unix::io::AsRawFd;
    let fd = socket.as_raw_fd();

    unsafe {
        let mut addr: libc::sockaddr_storage = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        let ret = libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len as *mut libc::socklen_t,
        );

        if ret != 0 {
            return Err(anyhow::anyhow!("Failed to get SO_ORIGINAL_DST: {}", std::io::Error::last_os_error()));
        }

        if addr.ss_family == libc::AF_INET as u16 {
            let addr_in = &addr as *const libc::sockaddr_storage as *const libc::sockaddr_in;
            let ip = std::net::Ipv4Addr::from((*addr_in).sin_addr.s_addr.to_be());
            let port = u16::from_be((*addr_in).sin_port);
            Ok(SocketAddr::new(std::net::IpAddr::V4(ip), port))
        } else {
            anyhow::bail!("Only IPv4 is supported");
        }
    }
}

/// Proxy a single TCP connection to the original destination
#[cfg(target_os = "linux")]
async fn proxy_connection(mut client: tokio::net::TcpStream, client_addr: SocketAddr) -> Result<()> {
    // Get the original destination before the redirect
    let original_dst = get_original_dst(&client)?;

    debug!("[REDIRECT PROXY] Connection from {} -> {} (original destination)",
           client_addr, original_dst);

    // Connect to the original destination
    match tokio::net::TcpStream::connect(original_dst).await {
        Ok(mut server) => {
            debug!("[REDIRECT PROXY] Connected to {}, relaying traffic", original_dst);

            let (mut client_read, mut client_write) = client.split();
            let (mut server_read, mut server_write) = server.split();

            // Relay data in both directions
            let client_to_server = tokio::io::copy(&mut client_read, &mut server_write);
            let server_to_client = tokio::io::copy(&mut server_read, &mut client_write);

            tokio::select! {
                res = client_to_server => {
                    if let Err(e) = res {
                        debug!("[REDIRECT PROXY] Client to {} error: {}", original_dst, e);
                    }
                }
                res = server_to_client => {
                    if let Err(e) = res {
                        debug!("[REDIRECT PROXY] {} to client error: {}", original_dst, e);
                    }
                }
            }

            debug!("[REDIRECT PROXY] Connection {} closed", original_dst);
        }
        Err(e) => {
            error!("[REDIRECT PROXY] Failed to connect to {}: {}", original_dst, e);
        }
    }

    Ok(())
}

/// Start TCP proxy server that handles redirected connections
#[cfg(target_os = "linux")]
async fn start_tcp_proxy(port: u16) -> Result<()> {
    let bind_addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&bind_addr).await?;

    info!("[REDIRECT PROXY] TCP proxy listening on {}", bind_addr);
    info!("[REDIRECT PROXY] Ready to accept redirected connections...");

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((client, client_addr)) => {
                        // Spawn a task for each connection
                        tokio::spawn(async move {
                            if let Err(e) = proxy_connection(client, client_addr).await {
                                error!("[REDIRECT PROXY] Proxy error for {}: {}", client_addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("[REDIRECT PROXY] Failed to accept connection: {}", e);
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("[REDIRECT PROXY] Shutting down...");
                break;
            }
        }
    }

    Ok(())
}

/// Setup iptables REDIRECT rules
#[cfg(target_os = "linux")]
async fn setup_redirect_rules(tun_if: &str, redirect_port: u16) -> Result<()> {
    info!("[REDIRECT PROXY] Setting up iptables REDIRECT rules...");

    // Clean up existing rules first
    cleanup_redirect_rules(tun_if, redirect_port).await;

    // Setup new rules
    let rules = vec![
        // Redirect TCP traffic from TUN interface to local proxy
        format!("-t nat -A PREROUTING -i {} -p tcp -j REDIRECT --to-port {}", tun_if, redirect_port),
        // Redirect TCP traffic from TUN interface (output) to local proxy
        format!("-t nat -A OUTPUT -o {} -p tcp -j REDIRECT --to-port {}", tun_if, redirect_port),
    ];

    for rule in &rules {
        let parts: Vec<&str> = rule.split_whitespace().collect();
        let result = Command::new("iptables")
            .args(&parts)
            .output()
            .await;

        match result {
            Ok(output) if output.status.success() => {
                info!("[REDIRECT PROXY] Added rule: {}", rule);
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                error!("[REDIRECT PROXY] Failed to add rule: {} - Error: {}", rule, stderr);
            }
            Err(e) => {
                error!("[REDIRECT PROXY] Failed to execute iptables: {}", e);
            }
        }
    }

    info!("[REDIRECT PROXY] iptables REDIRECT rules configured successfully");
    info!("[REDIRECT PROXY] TCP traffic from {} will be redirected to port {}", tun_if, redirect_port);

    Ok(())
}

/// Cleanup iptables REDIRECT rules
#[cfg(target_os = "linux")]
async fn cleanup_redirect_rules(tun_if: &str, redirect_port: u16) {
    info!("[REDIRECT PROXY] Cleaning up existing iptables REDIRECT rules...");

    let rules = vec![
        format!("-t nat -D PREROUTING -i {} -p tcp -j REDIRECT --to-port {}", tun_if, redirect_port),
        format!("-t nat -D OUTPUT -o {} -p tcp -j REDIRECT --to-port {}", tun_if, redirect_port),
    ];

    for rule in &rules {
        let parts: Vec<&str> = rule.split_whitespace().collect();
        let _ = Command::new("iptables")
            .args(&parts)
            .output()
            .await;
    }
}

// Stub implementations for non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub async fn start_redirect_proxy(_config: &ServerConfig) -> Result<()> {
    error!("[REDIRECT PROXY] REDIRECT proxy is only supported on Linux");
    anyhow::bail!("Platform not supported");
}

#[cfg(not(target_os = "linux"))]
async fn start_tcp_proxy(_port: u16) -> Result<()> {
    anyhow::bail!("Platform not supported");
}

#[cfg(not(target_os = "linux"))]
async fn setup_redirect_rules(_tun_if: &str, _redirect_port: u16) -> Result<()> {
    anyhow::bail!("Platform not supported");
}

#[cfg(not(target_os = "linux"))]
async fn cleanup_redirect_rules(_tun_if: &str, _redirect_port: u16) {
}
