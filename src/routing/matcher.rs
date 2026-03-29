//! 规则匹配器
//!
//! 实现 IP、端口、协议的匹配逻辑

use super::context::PacketContext;
use super::rule::{MatchCondition, Protocol, RoutingRule};
use ipnetwork::Ipv4Network;
use std::net::Ipv4Addr;

/// 规则匹配器
pub struct Matcher;

impl Matcher {
    /// 检查数据包是否匹配规则
    pub fn matches(rule: &RoutingRule, packet: &PacketContext) -> bool {
        if !rule.enabled {
            return false;
        }
        Self::matches_condition(&rule.match_cond, packet)
    }

    /// 检查数据包是否匹配条件
    pub fn matches_condition(cond: &MatchCondition, packet: &PacketContext) -> bool {
        // 所有条件必须同时满足 (AND 逻辑)

        // 检查 IP 匹配
        if let Some(ref dst_ip) = cond.dst_ip {
            if !Self::matches_ip(dst_ip, packet.dst_ip) {
                return false;
            }
        }

        // 检查端口匹配
        if let Some(ref dst_port) = cond.dst_port {
            if !Self::matches_port(dst_port, packet.dst_port) {
                return false;
            }
        }

        // 检查协议匹配
        if let Some(ref proto) = cond.protocol {
            if !Self::matches_protocol(proto, packet.protocol) {
                return false;
            }
        }

        true
    }

    /// 检查 IP 是否匹配 CIDR
    pub fn matches_ip(cidr: &str, ip: Ipv4Addr) -> bool {
        match cidr.parse::<Ipv4Network>() {
            Ok(network) => network.contains(ip),
            // 尝试作为单个 IP 地址解析
            Err(_) => {
                if let Ok(single_ip) = cidr.parse::<Ipv4Addr>() {
                    single_ip == ip
                } else {
                    false
                }
            }
        }
    }

    /// 检查端口是否匹配
    pub fn matches_port(port_spec: &str, packet_port: Option<u16>) -> bool {
        let port = match packet_port {
            Some(p) => p,
            None => return false,
        };

        match parse_port_range_internal(port_spec) {
            Ok((start, end)) => port >= start && port <= end,
            Err(_) => false,
        }
    }

    /// 检查协议是否匹配
    pub fn matches_protocol(proto_str: &str, packet_proto: Protocol) -> bool {
        match Protocol::from_str(proto_str) {
            Some(proto) => proto == packet_proto,
            None => false,
        }
    }
}

/// 解析端口范围（内部使用）
fn parse_port_range_internal(s: &str) -> Result<(u16, u16), String> {
    if s.contains('-') {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 2 {
            return Err("无效的范围格式".to_string());
        }
        let start: u16 = parts[0].parse().map_err(|_| "起始端口无效".to_string())?;
        let end: u16 = parts[1].parse().map_err(|_| "结束端口无效".to_string())?;
        if start > end {
            return Err("起始端口大于结束端口".to_string());
        }
        Ok((start, end))
    } else {
        let port: u16 = s.parse().map_err(|_| "端口无效".to_string())?;
        Ok((port, port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_ip() {
        assert!(Matcher::matches_ip(
            "10.0.0.0/8",
            "10.0.1.5".parse().unwrap()
        ));
        assert!(Matcher::matches_ip(
            "10.0.0.0/8",
            "10.255.255.255".parse().unwrap()
        ));
        assert!(!Matcher::matches_ip(
            "10.0.0.0/8",
            "192.168.1.1".parse().unwrap()
        ));
        assert!(Matcher::matches_ip(
            "192.168.0.0/16",
            "192.168.1.100".parse().unwrap()
        ));
        assert!(!Matcher::matches_ip(
            "192.168.0.0/16",
            "192.169.1.1".parse().unwrap()
        ));
        assert!(Matcher::matches_ip("1.2.3.4", "1.2.3.4".parse().unwrap()));
        assert!(!Matcher::matches_ip("1.2.3.4", "1.2.3.5".parse().unwrap()));
    }

    #[test]
    fn test_matches_port() {
        assert!(Matcher::matches_port("443", Some(443)));
        assert!(!Matcher::matches_port("443", Some(80)));
        assert!(Matcher::matches_port("1-1024", Some(22)));
        assert!(Matcher::matches_port("1-1024", Some(1024)));
        assert!(!Matcher::matches_port("1-1024", Some(1025)));
        assert!(!Matcher::matches_port("443", None));
    }

    #[test]
    fn test_matches_protocol() {
        assert!(Matcher::matches_protocol("tcp", Protocol::Tcp));
        assert!(Matcher::matches_protocol("udp", Protocol::Udp));
        assert!(Matcher::matches_protocol("icmp", Protocol::Icmp));
        assert!(!Matcher::matches_protocol("tcp", Protocol::Udp));
        assert!(!Matcher::matches_protocol("invalid", Protocol::Tcp));
    }
}
