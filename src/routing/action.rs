//! 路由动作类型定义
//!
//! 定义数据包的四种路由处理方式

use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

/// 路由动作类型，定义数据包的处理方式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoutingAction {
    /// 直连：绕过 VPN 隧道，直接发送到目标地址
    Direct,
    /// 内网：通过 VPN 隧道发送到内网目标
    Intranet,
    /// 代理：通过代理服务器转发
    Proxy,
    /// 丢弃：丢弃数据包并记录日志
    Drop,
}

impl Hash for RoutingAction {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
    }
}

impl Default for RoutingAction {
    fn default() -> Self {
        RoutingAction::Direct
    }
}

impl std::fmt::Display for RoutingAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoutingAction::Direct => write!(f, "direct"),
            RoutingAction::Intranet => write!(f, "intranet"),
            RoutingAction::Proxy => write!(f, "proxy"),
            RoutingAction::Drop => write!(f, "drop"),
        }
    }
}
