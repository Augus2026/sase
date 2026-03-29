//! 数据包分流规则引擎
//!
//! 提供高性能的数据包路由决策功能，支持：
//! - 基于 IP（CIDR）的规则匹配
//! - 基于端口的规则匹配（单端口和端口范围）
//! - 基于协议的规则匹配（TCP/UDP/ICMP）
//! - 多条件组合匹配（AND 逻辑）
//! - 规则优先级
//! - 配置热重载
//!
//! # 示例
//!
//! ```rust
//! use sase::routing::{RoutingEngine, PacketContext, RoutingAction};
//! use std::path::Path;
//!
//! // 加载规则引擎
//! let engine = RoutingEngine::from_file(Path::new("config/rules.toml"))?;
//!
//! // 构造数据包上下文
//! let packet = PacketContext::new(
//!     "192.168.1.100".parse().unwrap(),
//!     "10.0.0.5".parse().unwrap(),
//!     Some(54321),
//!     Some(80),
//!     sase::routing::Protocol::Tcp,
//! );
//!
//! // 匹配规则
//! let decision = engine.match_packet(&packet);
//!
//! // 处理结果
//! match decision.action {
//!     RoutingAction::Direct => println!("直连"),
//!     RoutingAction::Intranet => println!("走 VPN 隧道"),
//!     RoutingAction::Proxy => println!("走代理"),
//!     RoutingAction::Drop => println!("丢弃"),
//! }
//! ```

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
