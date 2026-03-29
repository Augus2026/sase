//! 路由模块库入口
//!
//! 该文件用于导出 routing 模块的公共 API

pub mod action;
pub mod config;
pub mod context;
pub mod decision;
pub mod engine;
pub mod matcher;
pub mod rule;

// 公共 API 导出
pub use action::RoutingAction;
pub use config::{ConfigError, RuleConfig};
pub use context::PacketContext;
pub use decision::RoutingDecision;
pub use engine::{HotReloadableEngine, RoutingEngine};
pub use rule::{MatchCondition, Protocol, RoutingRule};
