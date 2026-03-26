use log::info;
use tun2::{create_as_async, AsyncDevice, Configuration, Layer};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TunConfig {
    pub name: String,
    pub address: String,
    pub netmask: String,
    pub dns: Vec<String>,
    pub mtu: u32,
}

pub fn create_tun_device(tun_config: &TunConfig) -> anyhow::Result<AsyncDevice> {
    let address: std::net::Ipv4Addr = tun_config.address.parse()?;
    let netmask: std::net::Ipv4Addr = tun_config.netmask.parse()?;

    let mut config = Configuration::default();
    config
        .tun_name(&tun_config.name)
        .layer(Layer::L3)
        .mtu(tun_config.mtu as u16)
        .address(address)
        .netmask(netmask)
        .up();

    let device = create_as_async(&config)?;
    info!("TUN device created: {} -> {}", tun_config.name, tun_config.address);
    Ok(device)
}
