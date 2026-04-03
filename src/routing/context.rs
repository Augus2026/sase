//! 数据包上下文定义
//!
//! 从原始数据包提取的特征信息

use super::rule::Protocol;
use std::net::Ipv4Addr;

/// 待匹配的数据包特征，从实际数据包提取
#[derive(Debug, Clone)]
pub struct PacketContext {
    /// 源 IP 地址
    pub src_ip: Ipv4Addr,

    /// 目标 IP 地址
    pub dst_ip: Ipv4Addr,

    /// 源端口 (TCP/UDP)
    pub src_port: Option<u16>,

    /// 目标端口 (TCP/UDP)
    pub dst_port: Option<u16>,

    /// 协议类型
    pub protocol: Protocol,
}

impl PacketContext {
    /// 创建新的数据包上下文
    pub fn new(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        protocol: Protocol,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        }
    }

    /// 从原始 IP 包构造上下文
    ///
    /// 使用 etherparse 解析 IP 包头和传输层头部
    pub fn from_ip_packet(data: &[u8]) -> Option<Self> {
        // 使用 etherparse 解析 IP 数据包
        let sliced = etherparse::SlicedPacket::from_ip(data).ok()?;

        // 提取 IP 地址 - 从 net 字段获取
        let (src_ip, dst_ip) = match &sliced.net {
            Some(etherparse::InternetSlice::Ipv4(ipv4_slice)) => {
                // Ipv4Slice 包含 Ipv4Header，可以通过 header() 方法访问
                let header = ipv4_slice.header();
                let src = Ipv4Addr::from(header.source());
                let dst = Ipv4Addr::from(header.destination());
                (src, dst)
            }
            _ => return None,
        };

        // 默认值
        let mut src_port = None;
        let mut dst_port = None;
        let mut protocol = Protocol::Other(0);

        // 解析传输层
        if let Some(transport) = &sliced.transport {
            match transport {
                etherparse::TransportSlice::Tcp(tcp) => {
                    src_port = Some(tcp.source_port());
                    dst_port = Some(tcp.destination_port());
                    protocol = Protocol::Tcp;
                }
                etherparse::TransportSlice::Udp(udp) => {
                    src_port = Some(udp.source_port());
                    dst_port = Some(udp.destination_port());
                    protocol = Protocol::Udp;
                }
                etherparse::TransportSlice::Icmpv4(_icmp) => {
                    protocol = Protocol::Icmp;
                    // ICMP 不使用端口号
                    src_port = None;
                    dst_port = None;
                }
                etherparse::TransportSlice::Icmpv6(_) => {
                    // IPv6 ICMP 暂不支持
                    return None;
                }
            }
        }

        Some(Self::new(src_ip, dst_ip, src_port, dst_port, protocol))
    }
}

impl std::fmt::Display for PacketContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{} ({})",
            self.src_ip,
            self.src_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string()),
            self.dst_ip,
            self.dst_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string()),
            self.protocol
        )
    }
}
