use log::info;
use tun2::{create_as_async, AsyncDevice, Configuration, Layer};

#[derive(Debug, Clone)]
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

pub fn build_tun_config(client_id: u32, virtual_ip: &str) -> TunConfig {
    TunConfig {
        name: format!("tun{}", client_id),
        address: virtual_ip.to_string(),
        netmask: "255.255.255.0".to_string(),
        dns: vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
        mtu: 1500,
    }
}
