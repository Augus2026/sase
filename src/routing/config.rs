//! 配置解析定义
//!
//! TOML 配置文件的解析和验证

use super::action::RoutingAction;
use super::rule::{Protocol, RoutingRule};
use serde::{Deserialize, Serialize};
use std::io;

/// 配置错误类型
#[derive(Debug)]
pub enum ConfigError {
    /// 文件读取失败
    IoError(io::Error),
    /// TOML 解析失败
    ParseError(toml::de::Error),
    /// 规则验证失败
    ValidationError(String),
    /// 无效的 CIDR 表示
    InvalidCidr(String),
    /// 无效的端口范围
    InvalidPortRange(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::IoError(e) => write!(f, "文件读取失败: {}", e),
            ConfigError::ParseError(e) => write!(f, "TOML 解析失败: {}", e),
            ConfigError::ValidationError(msg) => write!(f, "规则验证失败: {}", msg),
            ConfigError::InvalidCidr(cidr) => write!(f, "无效的 CIDR 表示: {}", cidr),
            ConfigError::InvalidPortRange(range) => write!(f, "无效的端口范围: {}", range),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<io::Error> for ConfigError {
    fn from(e: io::Error) -> Self {
        ConfigError::IoError(e)
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(e: toml::de::Error) -> Self {
        ConfigError::ParseError(e)
    }
}

/// 默认路由动作
fn default_action() -> RoutingAction {
    RoutingAction::Direct
}

/// 规则配置文件的顶层结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    /// 默认路由动作 (无规则匹配时)
    #[serde(default = "default_action")]
    pub default_action: RoutingAction,

    /// 路由规则列表
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            default_action: RoutingAction::Direct,
            rules: Vec::new(),
        }
    }
}

impl RuleConfig {
    /// 从 TOML 字符串解析配置
    pub fn from_toml(toml_str: &str) -> Result<Self, ConfigError> {
        let config: RuleConfig = toml::from_str(toml_str)?;
        config.validate()?;
        Ok(config)
    }

    /// 从文件路径加载配置
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_toml(&content)
    }

    /// 验证配置
    pub fn validate(&self) -> Result<(), ConfigError> {
        for (index, rule) in self.rules.iter().enumerate() {
            // 验证匹配条件
            if !rule.match_cond.has_conditions() {
                return Err(ConfigError::ValidationError(format!(
                    "规则 '{}' (索引 {}) 没有任何匹配条件",
                    rule.name, index
                )));
            }

            // 验证 CIDR
            if let Some(ref cidr) = rule.match_cond.dst_ip {
                if let Err(e) = cidr.parse::<ipnetwork::Ipv4Network>() {
                    return Err(ConfigError::InvalidCidr(format!(
                        "规则 '{}' 的 dst_ip 无效: {} ({})",
                        rule.name, cidr, e
                    )));
                }
            }

            // 验证端口范围
            if let Some(ref port) = rule.match_cond.dst_port {
                if let Err(e) = parse_port_range(port) {
                    return Err(ConfigError::InvalidPortRange(format!(
                        "规则 '{}' 的 dst_port 无效: {} ({})",
                        rule.name, port, e
                    )));
                }
            }

            // 验证协议
            if let Some(ref proto) = rule.match_cond.protocol {
                if Protocol::from_str(proto).is_none() {
                    return Err(ConfigError::ValidationError(format!(
                        "规则 '{}' 的 protocol 无效: {} (必须是 tcp/udp/icmp)",
                        rule.name, proto
                    )));
                }
            }
        }

        Ok(())
    }

    /// 为规则分配 ID
    pub fn assign_ids(mut self) -> Self {
        let mut next_id = 1u32;
        for rule in &mut self.rules {
            if rule.id == 0 {
                rule.id = next_id;
            }
            next_id += 1;
        }
        self
    }
}

/// 解析端口范围字符串
///
/// 支持格式:
/// - 单端口: "443"
/// - 端口范围: "1-1024"
pub fn parse_port_range(s: &str) -> Result<(u16, u16), String> {
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
