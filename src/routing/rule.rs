//! 规则实体定义
//!
//! 包含 Protocol、MatchCondition、RoutingRule 等核心类型

use super::action::RoutingAction;
use serde::{Deserialize, Serialize};

/// 协议类型枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// TCP 协议
    Tcp,
    /// UDP 协议
    Udp,
    /// ICMP 协议
    Icmp,
    /// 其他协议（包含协议号）
    Other(u8),
}

// 为 Protocol 实现 From<u8> 以便从 IP 头的 protocol 字段转换
impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            1 => Protocol::Icmp,
            _ => Protocol::Other(value),
        }
    }
}

impl Protocol {
    /// 从字符串解析协议类型
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "tcp" => Some(Protocol::Tcp),
            "udp" => Some(Protocol::Udp),
            "icmp" => Some(Protocol::Icmp),
            _ => None,
        }
    }
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::Other(0)
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Icmp => write!(f, "icmp"),
            Protocol::Other(n) => write!(f, "other({})", n),
        }
    }
}

/// 规则匹配条件，支持 IP、端口、协议的组合匹配
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MatchCondition {
    /// 目标 IP 地址或 CIDR 范围 (可选)
    /// 例如: "10.0.0.0/8", "192.168.1.1"
    #[serde(rename = "dst_ip")]
    pub dst_ip: Option<String>,

    /// 目标端口或端口范围 (可选)
    /// 例如: "443", "1-1024"
    #[serde(rename = "dst_port")]
    pub dst_port: Option<String>,

    /// 协议类型 (可选)
    /// 可选值: "tcp", "udp", "icmp"
    pub protocol: Option<String>,
}

impl MatchCondition {
    /// 创建空的匹配条件
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置目标 IP
    pub fn with_dst_ip(mut self, ip: impl Into<String>) -> Self {
        self.dst_ip = Some(ip.into());
        self
    }

    /// 设置目标端口
    pub fn with_dst_port(mut self, port: impl Into<String>) -> Self {
        self.dst_port = Some(port.into());
        self
    }

    /// 设置协议
    pub fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    /// 检查是否有任何匹配条件
    pub fn has_conditions(&self) -> bool {
        self.dst_ip.is_some() || self.dst_port.is_some() || self.protocol.is_some()
    }
}

/// 单条路由规则，包含匹配条件和动作
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    /// 规则名称 (用于日志和调试)
    pub name: String,

    /// 规则 ID (自动生成或指定)
    #[serde(default)]
    pub id: u32,

    /// 优先级，数值越大优先级越高
    #[serde(default)]
    pub priority: u32,

    /// 匹配条件
    #[serde(rename = "match_cond")]
    pub match_cond: MatchCondition,

    /// 路由动作
    pub action: RoutingAction,

    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

impl RoutingRule {
    /// 创建新规则
    pub fn new(name: impl Into<String>, match_cond: MatchCondition, action: RoutingAction) -> Self {
        Self {
            name: name.into(),
            id: 0,
            priority: 0,
            match_cond,
            action,
            enabled: true,
        }
    }

    /// 设置规则 ID
    pub fn with_id(mut self, id: u32) -> Self {
        self.id = id;
        self
    }

    /// 设置优先级
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    /// 设置是否启用
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}
