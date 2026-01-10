//! Request/Response Transform Agent for Sentinel.
//!
//! This agent provides advanced request and response transformation capabilities:
//!
//! - URL rewriting with regex capture groups
//! - Header manipulation (add/set/remove)
//! - JSON body transformation (set, delete, rename, wrap)
//! - XML to JSON conversion
//! - Template-based responses
//! - Conditional transforms based on path, headers, body content
//!
//! ## Configuration Example
//!
//! ```yaml
//! rules:
//!   - name: "api-v1-rewrite"
//!     match:
//!       path: { pattern: "^/api/v1/(.*)$", type: regex }
//!     request:
//!       url:
//!         rewrite: "/api/v2/${1}"
//! ```

pub mod agent;
pub mod config;
pub mod context;
pub mod matcher;
pub mod rule;
pub mod transformer;

pub use agent::{TransformAgent, TransformAgentError};
pub use config::TransformConfig;
pub use context::TransformContext;
pub use rule::{RuleEngine, RuleError};
