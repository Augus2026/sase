//! 路由引擎核心
//!
//! 规则匹配和路由决策的核心逻辑

use log::{debug, info};
use std::path::Path;
use std::sync::{Arc, RwLock};

use super::action::RoutingAction;
use super::config::{ConfigError, RuleConfig};
use super::context::PacketContext;
use super::decision::RoutingDecision;
use super::matcher::Matcher;
use super::rule::RoutingRule;

/// 路由引擎，提供规则匹配和路由决策功能
pub struct RoutingEngine {
    /// 默认路由动作
    default_action: RoutingAction,
    /// 已排序的规则列表
    rules: Vec<RoutingRule>,
}

impl RoutingEngine {
    /// 从配置文件路径创建引擎
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let config = RuleConfig::from_file(path)?;
        Self::from_config(config)
    }

    /// 从配置对象创建引擎
    pub fn from_config(config: RuleConfig) -> Result<Self, ConfigError> {
        let config = config.assign_ids();

        // 按优先级排序（降序），相同优先级按原始顺序
        let mut rules = config.rules;
        rules.sort_by(|a, b| b.priority.cmp(&a.priority).then_with(|| a.id.cmp(&b.id)));

        debug!("路由引擎初始化完成，共 {} 条规则", rules.len());

        Ok(Self {
            default_action: config.default_action,
            rules,
        })
    }

    /// 匹配数据包并返回路由决策
    pub fn match_packet(&self, packet: &PacketContext) -> RoutingDecision {
        // 遍历规则列表（已按优先级排序）
        for rule in &self.rules {
            if Matcher::matches(rule, packet) {
                debug!(
                    "数据包 {} 匹配规则 '{}' (id={}, priority={})",
                    packet, rule.name, rule.id, rule.priority
                );

                // 记录丢弃动作日志
                if rule.action == RoutingAction::Drop {
                    info!(
                        "[DROP] src={} dst={} rule=\"{}\" rule_id={}",
                        packet.src_ip, packet.dst_ip, rule.name, rule.id
                    );
                }

                return RoutingDecision::from_rule(rule.id, rule.name.clone(), rule.action);
            }
        }

        // 无匹配规则，使用默认动作
        debug!(
            "数据包 {} 无匹配规则，使用默认动作: {}",
            packet, self.default_action
        );

        // 记录默认丢弃日志
        if self.default_action == RoutingAction::Drop {
            info!(
                "[DROP] src={} dst={} rule=\"default\"",
                packet.src_ip, packet.dst_ip
            );
        }

        RoutingDecision::default_action(self.default_action)
    }

    /// 获取当前规则数量
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// 获取默认路由动作
    pub fn default_action(&self) -> RoutingAction {
        self.default_action
    }
}

/// 支持热重载的路由引擎包装器
pub struct HotReloadableEngine {
    inner: Arc<RwLock<RoutingEngine>>,
}

impl HotReloadableEngine {
    /// 从配置文件创建可热重载的引擎
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let engine = RoutingEngine::from_file(path)?;
        Ok(Self {
            inner: Arc::new(RwLock::new(engine)),
        })
    }

    /// 从配置对象创建可热重载的引擎
    pub fn from_config(config: RuleConfig) -> Result<Self, ConfigError> {
        let engine = RoutingEngine::from_config(config)?;
        Ok(Self {
            inner: Arc::new(RwLock::new(engine)),
        })
    }

    /// 匹配数据包
    pub fn match_packet(&self, packet: &PacketContext) -> RoutingDecision {
        let engine = self.inner.read().unwrap();
        engine.match_packet(packet)
    }

    /// 热重载配置
    pub fn reload(&self, path: &Path) -> Result<(), ConfigError> {
        let new_engine = RoutingEngine::from_file(path)?;
        let mut engine = self.inner.write().unwrap();
        info!("路由引擎热重载完成，共 {} 条规则", new_engine.rule_count());
        *engine = new_engine;
        Ok(())
    }

    /// 获取内部引擎的克隆（用于共享）
    pub fn inner(&self) -> Arc<RwLock<RoutingEngine>> {
        self.inner.clone()
    }

    /// 获取规则数量
    pub fn rule_count(&self) -> usize {
        self.inner.read().unwrap().rule_count()
    }

    /// 获取默认动作
    pub fn default_action(&self) -> RoutingAction {
        self.inner.read().unwrap().default_action()
    }
}

impl Clone for HotReloadableEngine {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::rule::{MatchCondition, Protocol};
    use super::*;

    fn create_test_engine() -> RoutingEngine {
        let mut rules = vec![
            RoutingRule::new(
                "内网流量",
                MatchCondition::default().with_dst_ip("10.0.0.0/8"),
                RoutingAction::Intranet,
            )
            .with_id(1)
            .with_priority(100),
            RoutingRule::new(
                "HTTPS代理",
                MatchCondition::default().with_dst_port("443"),
                RoutingAction::Proxy,
            )
            .with_id(2)
            .with_priority(50),
        ];

        rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        RoutingEngine {
            default_action: RoutingAction::Direct,
            rules,
        }
    }

    #[test]
    fn test_match_ip_rule() {
        let engine = create_test_engine();

        let packet = PacketContext::new(
            "192.168.1.1".parse().unwrap(),
            "10.0.1.5".parse().unwrap(),
            Some(12345),
            Some(80),
            Protocol::Tcp,
        );

        let decision = engine.match_packet(&packet);
        assert_eq!(decision.action, RoutingAction::Intranet);
        assert_eq!(decision.rule_id, Some(1));
    }

    #[test]
    fn test_match_default() {
        let engine = create_test_engine();

        let packet = PacketContext::new(
            "192.168.1.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            Some(12345),
            Some(80),
            Protocol::Tcp,
        );

        let decision = engine.match_packet(&packet);
        assert_eq!(decision.action, RoutingAction::Direct);
        assert!(decision.is_default);
    }

    #[test]
    fn test_match_port_rule() {
        let engine = create_test_engine();

        let packet = PacketContext::new(
            "192.168.1.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            Some(12345),
            Some(443),
            Protocol::Tcp,
        );

        let decision = engine.match_packet(&packet);
        assert_eq!(decision.action, RoutingAction::Proxy);
        assert_eq!(decision.rule_id, Some(2));
    }

    #[test]
    fn test_rule_count() {
        let engine = create_test_engine();
        assert_eq!(engine.rule_count(), 2);
    }

    #[test]
    fn test_default_action() {
        let engine = create_test_engine();
        assert_eq!(engine.default_action(), RoutingAction::Direct);
    }
}
