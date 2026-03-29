//! 路由决策定义
//!
//! 规则匹配的结果

use super::action::RoutingAction;
use std::time::Instant;

/// 规则匹配的结果
#[derive(Debug, Clone)]
pub struct RoutingDecision {
    /// 路由动作
    pub action: RoutingAction,

    /// 匹配的规则 ID (如果匹配)
    pub rule_id: Option<u32>,

    /// 匹配的规则名称 (用于日志)
    pub rule_name: Option<String>,

    /// 决策时间戳
    pub timestamp: Instant,

    /// 是否为默认路由
    pub is_default: bool,
}

impl RoutingDecision {
    /// 创建默认路由决策
    pub fn default_action(action: RoutingAction) -> Self {
        Self {
            action,
            rule_id: None,
            rule_name: None,
            timestamp: Instant::now(),
            is_default: true,
        }
    }

    /// 创建匹配规则的决策
    pub fn from_rule(rule_id: u32, rule_name: String, action: RoutingAction) -> Self {
        Self {
            action,
            rule_id: Some(rule_id),
            rule_name: Some(rule_name),
            timestamp: Instant::now(),
            is_default: false,
        }
    }

    /// 是否为丢弃动作
    pub fn is_drop(&self) -> bool {
        self.action == RoutingAction::Drop
    }

    /// 获取匹配的规则 ID (如果非默认路由)
    pub fn rule_id(&self) -> Option<u32> {
        self.rule_id
    }
}

impl std::fmt::Display for RoutingDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_default {
            write!(f, "default -> {}", self.action)
        } else {
            write!(
                f,
                "rule '{}' (id={}) -> {}",
                self.rule_name.as_deref().unwrap_or("unknown"),
                self.rule_id.unwrap_or(0),
                self.action
            )
        }
    }
}
