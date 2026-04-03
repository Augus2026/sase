use super::config::parse_port_range;
use super::context::PacketContext;
use super::rule::{MatchCondition, Protocol, RoutingRule};
use ipnetwork::Ipv4Network;
use std::net::Ipv4Addr;

pub struct Matcher;

impl Matcher {
    pub fn matches(rule: &RoutingRule, packet: &PacketContext) -> bool {
        rule.enabled && Self::matches_condition(&rule.match_cond, packet)
    }

    pub fn matches_condition(cond: &MatchCondition, packet: &PacketContext) -> bool {
        if let Some(ref dst_ip) = cond.dst_ip {
            if !Self::matches_ip(dst_ip, packet.dst_ip) {
                return false;
            }
        }

        if let Some(ref dst_port) = cond.dst_port {
            if !Self::matches_port(dst_port, packet.dst_port) {
                return false;
            }
        }

        if let Some(ref proto) = cond.protocol {
            if !Self::matches_protocol(proto, packet.protocol) {
                return false;
            }
        }

        true
    }

    pub fn matches_ip(cidr: &str, ip: Ipv4Addr) -> bool {
        match cidr.parse::<Ipv4Network>() {
            Ok(network) => network.contains(ip),
            Err(_) => cidr.parse::<Ipv4Addr>() == Ok(ip),
        }
    }

    pub fn matches_port(port_spec: &str, packet_port: Option<u16>) -> bool {
        let Some(port) = packet_port else {
            return false;
        };

        match parse_port_range(port_spec) {
            Ok((start, end)) => (start..=end).contains(&port),
            Err(_) => false,
        }
    }

    pub fn matches_protocol(proto_str: &str, packet_proto: Protocol) -> bool {
        match Protocol::from_str(proto_str) {
            Some(proto) => proto == packet_proto,
            None => false,
        }
    }
}
