use log::{debug, info};
use std::path::Path;
use std::sync::{Arc, RwLock};

use super::action::RoutingAction;
use super::config::{ConfigError, RuleConfig};
use super::context::PacketContext;
use super::decision::RoutingDecision;
use super::matcher::Matcher;
use super::rule::RoutingRule;

pub struct RoutingEngine {
    default_action: RoutingAction,
    rules: Vec<RoutingRule>,
}

impl RoutingEngine {
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let config = RuleConfig::from_file(path)?;
        Self::from_config(config)
    }

    pub fn from_config(config: RuleConfig) -> Result<Self, ConfigError> {
        let config = config.assign_ids();
        let mut rules = config.rules;
        rules.sort_by(|a, b| b.priority.cmp(&a.priority).then_with(|| a.id.cmp(&b.id)));

        debug!("routing engine initialized with {} rules", rules.len());

        Ok(Self {
            default_action: config.default_action,
            rules,
        })
    }

    pub fn match_packet(&self, packet: &PacketContext) -> RoutingDecision {
        for rule in &self.rules {
            if Matcher::matches(rule, packet) {
                debug!(
                    "packet {} matched rule \"{}\" (id={}, priority={})",
                    packet, rule.name, rule.id, rule.priority
                );

                if rule.action == RoutingAction::Drop {
                    info!(
                        "[DROP] src={} dst={} rule=\"{}\" rule_id={}",
                        packet.src_ip, packet.dst_ip, rule.name, rule.id
                    );
                }

                return RoutingDecision::from_rule(rule.id, rule.name.clone(), rule.action);
            }
        }

        debug!(
            "packet {} matched no rule, using default action {}",
            packet, self.default_action
        );

        if self.default_action == RoutingAction::Drop {
            info!(
                "[DROP] src={} dst={} rule=\"default\"",
                packet.src_ip, packet.dst_ip
            );
        }

        RoutingDecision::default_action(self.default_action)
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn default_action(&self) -> RoutingAction {
        self.default_action
    }
}

pub struct HotReloadableEngine {
    inner: Arc<RwLock<RoutingEngine>>,
}

impl HotReloadableEngine {
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let engine = RoutingEngine::from_file(path)?;
        Ok(Self {
            inner: Arc::new(RwLock::new(engine)),
        })
    }

    pub fn match_packet(&self, packet: &PacketContext) -> RoutingDecision {
        self.inner.read().unwrap().match_packet(packet)
    }

    pub fn reload(&self, path: &Path) -> Result<(), ConfigError> {
        let new_engine = RoutingEngine::from_file(path)?;
        info!(
            "routing engine reloaded with {} rules",
            new_engine.rule_count()
        );
        *self.inner.write().unwrap() = new_engine;
        Ok(())
    }

    pub fn rule_count(&self) -> usize {
        self.inner.read().unwrap().rule_count()
    }

    pub fn default_action(&self) -> RoutingAction {
        self.inner.read().unwrap().default_action()
    }
}

#[cfg(test)]
mod tests {
    use super::super::config::RuleConfig;
    use super::super::rule::Protocol;
    use super::*;

    fn create_test_engine() -> RoutingEngine {
        RoutingEngine::from_config(
            RuleConfig::from_toml(
                r#"
default_action = "direct"

[[rules]]
name = "ssh drop"
priority = 200
match_cond = { dst_port = "22", protocol = "tcp" }
action = "drop"

[[rules]]
name = "intranet"
priority = 100
match_cond = { dst_ip = "10.0.0.0/8" }
action = "intranet"

[[rules]]
name = "https proxy"
priority = 50
match_cond = { dst_port = "443" }
action = "proxy"
"#,
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn test_matches_highest_priority_rule() {
        let engine = create_test_engine();
        let packet = PacketContext::new(
            "192.168.1.1".parse().unwrap(),
            "10.0.1.5".parse().unwrap(),
            Some(12345),
            Some(22),
            Protocol::Tcp,
        );

        let decision = engine.match_packet(&packet);
        assert_eq!(decision.action, RoutingAction::Drop);
        assert_eq!(decision.rule_id, Some(1));
    }

    #[test]
    fn test_uses_default_action_when_no_rule_matches() {
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
    fn test_matches_port_rule() {
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
        assert_eq!(decision.rule_name.as_deref(), Some("https proxy"));
    }
}
