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

pub fn serialize_tun_config(tun_config: &TunConfig) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(tun_config.name.as_bytes());
    data.push(0);
    data.extend_from_slice(tun_config.address.as_bytes());
    data.push(0);
    data.extend_from_slice(tun_config.netmask.as_bytes());
    data.push(0);
    for dns in &tun_config.dns {
        data.extend_from_slice(dns.as_bytes());
        data.push(0);
    }
    data.extend_from_slice(&tun_config.mtu.to_be_bytes());
    data
}

pub fn deserialize_tun_config(data: &[u8]) -> Option<TunConfig> {
    let mut pos = 0;

    let name_end = data[pos..].iter().position(|&b| b == 0)?;
    let name = String::from_utf8(data[pos..pos + name_end].to_vec()).ok()?;
    pos += name_end + 1;

    if pos >= data.len() {
        return None;
    }
    let address_end = data[pos..].iter().position(|&b| b == 0)?;
    let address = String::from_utf8(data[pos..pos + address_end].to_vec()).ok()?;
    pos += address_end + 1;

    if pos >= data.len() {
        return None;
    }
    let netmask_end = data[pos..].iter().position(|&b| b == 0)?;
    let netmask = String::from_utf8(data[pos..pos + netmask_end].to_vec()).ok()?;
    pos += netmask_end + 1;

    let mut dns = Vec::new();

    while pos + 4 < data.len() {
        if pos >= data.len() {
            break;
        }

        let dns_end = data[pos..].iter().position(|&b| b == 0)?;
        if dns_end == 0 {
            pos += 1;
            continue;
        }
        if pos + dns_end + 1 > data.len() - 4 {
            break;
        }
        let dns_str = String::from_utf8(data[pos..pos + dns_end].to_vec()).ok()?;
        if !dns_str.is_empty() {
            dns.push(dns_str);
        }
        pos += dns_end + 1;
    }

    if pos + 4 > data.len() {
        return None;
    }
    let mtu = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);

    Some(TunConfig {
        name,
        address,
        netmask,
        dns,
        mtu,
    })
}
