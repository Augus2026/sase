use crate::common::{ServerConfig, TUN_MTU};
use anyhow::{Context, Result};
use log::{info, warn};
use std::io;
use tun2::{AsyncDevice, Configuration};

/// Create and configure a TUN device
pub fn create_tun_device(config: &ServerConfig) -> Result<AsyncDevice> {
    info!("Creating TUN device: {}", config.tun_name);

    let mut tun_config = Configuration::default();

    tun_config
        .name(&config.tun_name)
        .layer(tun2::Layer::L3)
        .mtu(config.mtu as u16)
        .address(config.tun_addr)
        .netmask(config.tun_netmask)
        .up();

    // #[cfg(target_os = "linux")]
    // {
    //     tun_config.platform_specific(|config| {
    //         // Linux-specific configuration
    //     });
    // }

    let tun = tun_config.create_async().context("Failed to create TUN device")?;

    info!(
        "TUN device created: {} -> {}",
        config.tun_name, config.tun_addr
    );

    Ok(tun)
}

/// Helper to allocate buffer for packet reading
pub fn new_packet_buffer() -> Vec<u8> {
    vec![0u8; TUN_MTU]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_size() {
        let buf = new_packet_buffer();
        assert_eq!(buf.len(), TUN_MTU);
    }
}
