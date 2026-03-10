use log::{debug, info, warn};
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
    let config = build_tun2_config(tun_config)?;
    let device = create_as_async(&config)?;
    info!("TUN device created: {} -> {}", tun_config.name, tun_config.address);
    Ok(device)
}

pub fn build_tun2_config(tun_config: &TunConfig) -> anyhow::Result<Configuration> {
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

    Ok(config)
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
    data.push(0); // null terminator for name
    data.extend_from_slice(tun_config.address.as_bytes());
    data.push(0); // null terminator for address
    data.extend_from_slice(tun_config.netmask.as_bytes());
    data.push(0); // null terminator for netmask
    for dns in &tun_config.dns {
        data.extend_from_slice(dns.as_bytes());
        data.push(0); // null terminator for each dns
    }
    data.extend_from_slice(&tun_config.mtu.to_be_bytes());
    data
}

pub fn deserialize_tun_config(data: &[u8]) -> Option<TunConfig> {
    let mut pos = 0;

    debug!("parse_tun_config: Starting with {} bytes", data.len());
    debug!("parse_tun_config: Raw data: {:?}", data);

    // Parse name (null-terminated string)
    let name_end = data[pos..].iter().position(|&b| b == 0)?;
    let name = String::from_utf8(data[pos..pos + name_end].to_vec()).ok()?;
    debug!("parse_tun_config: name='{}', pos={}", name, pos);
    pos += name_end + 1;

    // Parse address (null-terminated string)
    if pos >= data.len() {
        warn!("parse_tun_config: Reached end of data while parsing address");
        return None;
    }
    let address_end = data[pos..].iter().position(|&b| b == 0)?;
    let address = String::from_utf8(data[pos..pos + address_end].to_vec()).ok()?;
    debug!("parse_tun_config: address='{}', pos={}", address, pos);
    pos += address_end + 1;

    // Parse netmask (null-terminated string)
    if pos >= data.len() {
        warn!("parse_tun_config: Reached end of data while parsing netmask");
        return None;
    }
    let netmask_end = data[pos..].iter().position(|&b| b == 0)?;
    let netmask = String::from_utf8(data[pos..pos + netmask_end].to_vec()).ok()?;
    debug!("parse_tun_config: netmask='{}', pos={}", netmask, pos);
    pos += netmask_end + 1;

    // Parse DNS entries (multiple null-terminated strings until we reach the mtu)
    let mut dns = Vec::new();
    debug!("parse_tun_config: Starting DNS parsing at pos={}", pos);

    while pos + 4 < data.len() { // Need at least 4 bytes for mtu after DNS
        if pos >= data.len() {
            break;
        }

        let dns_end = data[pos..].iter().position(|&b| b == 0)?;
        if dns_end == 0 {
            pos += 1; // Skip consecutive null terminators
            continue;
        }
        if pos + dns_end + 1 > data.len() - 4 {
            debug!("parse_tun_config: Not enough space for DNS + null terminator + mtu");
            break;
        }
        let dns_str = String::from_utf8(data[pos..pos + dns_end].to_vec()).ok()?;
        if !dns_str.is_empty() {
            debug!("parse_tun_config: DNS entry='{}', pos={}", dns_str, pos);
            dns.push(dns_str);
        }
        pos += dns_end + 1;
    }

    debug!("parse_tun_config: DNS parsing complete at pos={}", pos);

    // Parse MTU (4 bytes)
    if pos + 4 > data.len() {
        warn!("parse_tun_config: Not enough data for MTU at pos={}, data.len()={}", pos, data.len());
        return None;
    }
    let mtu = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    debug!("parse_tun_config: mtu={}", mtu);

    Some(TunConfig {
        name,
        address,
        netmask,
        dns,
        mtu,
    })
}
