use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoutingAction {
    Direct,
    Proxy,
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
            RoutingAction::Proxy => write!(f, "proxy"),
            RoutingAction::Drop => write!(f, "drop"),
        }
    }
}
