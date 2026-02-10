//! NAT-based transparent proxy implementation
//!
//! This module implements transparent proxying using Linux NAT/MASQUERADE.
//! In this mode, the kernel handles packet forwarding and NAT translation.
//!
//! Architecture:
//! TUN interface -> [Kernel Forwarding] -> Physical Interface (MASQUERADE) -> Internet
//!
//! Pros:
//! - Simple setup, kernel handles the heavy lifting
//! - Good performance (kernel-level forwarding)
//! - No application-layer overhead
//!
//! Cons:
//! - Cannot inspect/modify traffic at application layer
//! - Less control over connections
//! - Pure routing mode, not a true "proxy"

use anyhow::Result;
use log::{info, error};
use crate::common::ServerConfig;

/// Start NAT-based transparent proxy
///
/// This enables IP forwarding and sets up iptables rules for MASQUERADE.
/// All traffic from TUN interface will be NATed and forwarded through the physical interface.
#[cfg(target_os = "linux")]
pub async fn start_nat_proxy(config: &ServerConfig) -> Result<()> {
    let tun_if = &config.tun_name;
    let physical_if = detect_physical_interface().await?;

    info!("[NAT PROXY] Starting NAT-based transparent proxy");
    info!("[NAT PROXY] TUN interface: {}", tun_if);
    info!("[NAT PROXY] Physical interface: {}", physical_if);

    // Enable IP forwarding
    enable_ip_forwarding().await?;

    // Setup iptables rules
    setup_nat_rules(tun_if, &physical_if).await?;

    info!("[NAT PROXY] NAT mode enabled - kernel will handle packet forwarding");
    info!("[NAT PROXY] Traffic from {} will be MASQUERADE'd through {}", tun_if, physical_if);

    // Keep task alive - kernel handles the actual forwarding
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("[NAT PROXY] Shutting down, cleaning up iptables rules...");
            cleanup_nat_rules(tun_if, &physical_if).await?;
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
async fn enable_ip_forwarding() -> Result<()> {
    info!("[NAT PROXY] Enabling IPv4 forwarding...");

    tokio::fs::write("/proc/sys/net/ipv4/ip_forward", b"1").await?;

    info!("[NAT PROXY] IPv4 forwarding enabled");
    Ok(())
}

#[cfg(target_os = "linux")]
async fn detect_physical_interface() -> Result<String> {
    // Try to detect the physical interface by looking at routing table
    let output = Command::new("ip")
        .args(&["route", "show", "default"])
        .output()
        .await?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse output like: "default via 192.168.1.1 dev ens33 proto dhcp ..."
        for line in stdout.lines() {
            if let Some(dev_pos) = line.find("dev ") {
                let rest = &line[dev_pos + 4..];
                if let Some(space_pos) = rest.find(' ') {
                    let iface = rest[..space_pos].trim();
                    if !iface.is_empty() && iface != "lo" {
                        info!("[NAT PROXY] Auto-detected physical interface: {}", iface);
                        return Ok(iface.to_string());
                    }
                }
            }
        }
    }

    // Fallback to common interface names
    let common_interfaces = vec!["ens33", "eth0", "enp0s3", "ens18", "wlan0"];
    for iface in common_interfaces {
        if check_interface_exists(iface).await {
            info!("[NAT PROXY] Using detected physical interface: {}", iface);
            return Ok(iface.to_string());
        }
    }

    warn!("[NAT PROXY] Could not auto-detect physical interface, using 'eth0' as default");
    Ok("eth0".to_string())
}

#[cfg(target_os = "linux")]
async fn check_interface_exists(iface: &str) -> bool {
    let output = Command::new("ip")
        .args(&["link", "show", iface])
        .output()
        .await;

    match output {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

#[cfg(target_os = "linux")]
async fn setup_nat_rules(tun_if: &str, physical_if: &str) -> Result<()> {
    info!("[NAT PROXY] Setting up iptables NAT rules...");

    // Clean up any existing rules first
    cleanup_nat_rules(tun_if, physical_if).await;

    // Setup new rules
    let rules = vec![
        // Allow forwarding from TUN to physical
        format!("-t filter -A FORWARD -i {} -o {} -j ACCEPT", tun_if, physical_if),
        format!("-t filter -A FORWARD -o {} -i {} -j ACCEPT", tun_if, physical_if),
        format!("-t filter -A FORWARD -i {} -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT", physical_if, tun_if),
        // MASQUERADE traffic going out physical interface
        format!("-t nat -A POSTROUTING -o {} -j MASQUERADE", physical_if),
    ];

    for rule in &rules {
        let parts: Vec<&str> = rule.split_whitespace().collect();
        let result = Command::new("iptables")
            .args(&parts)
            .output()
            .await;

        match result {
            Ok(output) if output.status.success() => {
                info!("[NAT PROXY] Added rule: {}", rule);
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                error!("[NAT PROXY] Failed to add rule: {} - Error: {}", rule, stderr);
            }
            Err(e) => {
                error!("[NAT PROXY] Failed to execute iptables: {}", e);
            }
        }
    }

    info!("[NAT PROXY] iptables NAT rules configured successfully");
    Ok(())
}

#[cfg(target_os = "linux")]
async fn cleanup_nat_rules(tun_if: &str, physical_if: &str) {
    info!("[NAT PROXY] Cleaning up existing iptables rules...");

    let rules = vec![
        format!("-t nat -D POSTROUTING -o {} -j MASQUERADE", physical_if),
        format!("-t filter -D FORWARD -i {} -o {} -j ACCEPT", tun_if, physical_if),
        format!("-t filter -D FORWARD -o {} -i {} -j ACCEPT", tun_if, physical_if),
        format!("-t filter -D FORWARD -i {} -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT", physical_if, tun_if),
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
pub async fn start_nat_proxy(_config: &ServerConfig) -> Result<()> {
    error!("[NAT PROXY] NAT proxy is only supported on Linux");
    anyhow::bail!("Platform not supported");
}

#[cfg(not(target_os = "linux"))]
async fn enable_ip_forwarding() -> Result<()> {
    anyhow::bail!("Platform not supported")
}

#[cfg(not(target_os = "linux"))]
async fn detect_physical_interface() -> Result<String> {
    anyhow::bail!("Platform not supported")
}

#[cfg(not(target_os = "linux"))]
async fn setup_nat_rules(_tun_if: &str, _physical_if: &str) -> Result<()> {
    anyhow::bail!("Platform not supported")
}

#[cfg(not(target_os = "linux"))]
async fn cleanup_nat_rules(_tun_if: &str, _physical_if: &str) {
}
