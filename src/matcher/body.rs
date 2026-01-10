//! Body matching implementation.

use super::{MatchResult, Matcher, MatcherError};
use crate::config::{BodyMatcher, JsonCondition};
use crate::context::TransformContext;
use async_trait::async_trait;
use serde_json::Value as JsonValue;

/// Compiled body matcher.
pub struct BodyMatcherImpl {
    /// JSON conditions to check
    conditions: Vec<CompiledJsonCondition>,
}

struct CompiledJsonCondition {
    path: String,
    check: JsonCheck,
}

enum JsonCheck {
    Equals(JsonValue),
    Contains(String),
    Exists,
    NotExists,
}

impl BodyMatcherImpl {
    /// Compile a body matcher from configuration.
    pub fn compile(config: &BodyMatcher) -> Result<Self, MatcherError> {
        let conditions = config.json.as_ref()
            .map(|conds| conds.iter().map(|c| compile_condition(c)).collect())
            .unwrap_or_default();

        Ok(Self { conditions })
    }
}

fn compile_condition(config: &JsonCondition) -> CompiledJsonCondition {
    let check = if let Some(ref value) = config.equals {
        JsonCheck::Equals(value.clone())
    } else if let Some(ref substr) = config.contains {
        JsonCheck::Contains(substr.clone())
    } else if config.exists == Some(false) {
        JsonCheck::NotExists
    } else {
        JsonCheck::Exists
    };

    CompiledJsonCondition {
        path: config.path.clone(),
        check,
    }
}

/// Extract a value from JSON using a simple path expression.
/// Supports: $.field, $.field.subfield, $.array[0]
fn get_json_value<'a>(json: &'a JsonValue, path: &str) -> Option<&'a JsonValue> {
    let path = path.trim_start_matches("$.");
    let path = path.trim_start_matches('$');

    if path.is_empty() {
        return Some(json);
    }

    let mut current = json;

    for part in path.split('.') {
        if part.is_empty() {
            continue;
        }

        // Handle array indexing like "items[0]"
        if let Some(bracket_pos) = part.find('[') {
            let key = &part[..bracket_pos];
            let idx_str = part[bracket_pos + 1..].trim_end_matches(']');

            if !key.is_empty() {
                current = current.get(key)?;
            }

            let idx: usize = idx_str.parse().ok()?;
            current = current.get(idx)?;
        } else {
            current = current.get(part)?;
        }
    }

    Some(current)
}

fn check_condition(json: &JsonValue, condition: &CompiledJsonCondition) -> bool {
    let value = get_json_value(json, &condition.path);

    match &condition.check {
        JsonCheck::Equals(expected) => {
            value.map_or(false, |v| v == expected)
        }
        JsonCheck::Contains(substr) => {
            value.map_or(false, |v| {
                match v {
                    JsonValue::String(s) => s.contains(substr),
                    _ => v.to_string().contains(substr),
                }
            })
        }
        JsonCheck::Exists => value.is_some(),
        JsonCheck::NotExists => value.is_none(),
    }
}

#[async_trait]
impl Matcher for BodyMatcherImpl {
    async fn matches(&self, ctx: &TransformContext) -> MatchResult {
        let json = match &ctx.body_json {
            Some(j) => j,
            None => return MatchResult::not_matched(),
        };

        for condition in &self.conditions {
            if !check_condition(json, condition) {
                return MatchResult::not_matched();
            }
        }

        MatchResult::matched()
    }

    fn name(&self) -> &'static str {
        "body_matcher"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::RequestInfo;
    use std::collections::HashMap;

    fn make_context(body: JsonValue) -> TransformContext {
        let request = RequestInfo {
            method: "POST".to_string(),
            path: "/test".to_string(),
            query_string: None,
            query_params: HashMap::new(),
            headers: HashMap::new(),
            client_ip: "127.0.0.1".to_string(),
        };
        TransformContext::new(request, "test".to_string())
            .with_body_json(body)
    }

    #[tokio::test]
    async fn test_equals() {
        let config = BodyMatcher {
            json: Some(vec![JsonCondition {
                path: "$.type".to_string(),
                equals: Some(serde_json::json!("user")),
                contains: None,
                exists: None,
            }]),
        };
        let matcher = BodyMatcherImpl::compile(&config).unwrap();

        let ctx = make_context(serde_json::json!({ "type": "user", "id": 123 }));
        assert!(matcher.matches(&ctx).await.matched);

        let ctx = make_context(serde_json::json!({ "type": "admin", "id": 123 }));
        assert!(!matcher.matches(&ctx).await.matched);
    }

    #[tokio::test]
    async fn test_nested_path() {
        let config = BodyMatcher {
            json: Some(vec![JsonCondition {
                path: "$.user.role".to_string(),
                equals: Some(serde_json::json!("admin")),
                contains: None,
                exists: None,
            }]),
        };
        let matcher = BodyMatcherImpl::compile(&config).unwrap();

        let ctx = make_context(serde_json::json!({
            "user": { "role": "admin", "name": "John" }
        }));
        assert!(matcher.matches(&ctx).await.matched);
    }

    #[tokio::test]
    async fn test_array_index() {
        let config = BodyMatcher {
            json: Some(vec![JsonCondition {
                path: "$.items[0]".to_string(),
                equals: Some(serde_json::json!("first")),
                contains: None,
                exists: None,
            }]),
        };
        let matcher = BodyMatcherImpl::compile(&config).unwrap();

        let ctx = make_context(serde_json::json!({
            "items": ["first", "second", "third"]
        }));
        assert!(matcher.matches(&ctx).await.matched);
    }

    #[tokio::test]
    async fn test_exists() {
        let config = BodyMatcher {
            json: Some(vec![JsonCondition {
                path: "$.auth_token".to_string(),
                equals: None,
                contains: None,
                exists: Some(true),
            }]),
        };
        let matcher = BodyMatcherImpl::compile(&config).unwrap();

        let ctx = make_context(serde_json::json!({ "auth_token": "abc123" }));
        assert!(matcher.matches(&ctx).await.matched);

        let ctx = make_context(serde_json::json!({ "other": "value" }));
        assert!(!matcher.matches(&ctx).await.matched);
    }

    #[tokio::test]
    async fn test_contains() {
        let config = BodyMatcher {
            json: Some(vec![JsonCondition {
                path: "$.message".to_string(),
                equals: None,
                contains: Some("error".to_string()),
                exists: None,
            }]),
        };
        let matcher = BodyMatcherImpl::compile(&config).unwrap();

        let ctx = make_context(serde_json::json!({ "message": "An error occurred" }));
        assert!(matcher.matches(&ctx).await.matched);

        let ctx = make_context(serde_json::json!({ "message": "Success" }));
        assert!(!matcher.matches(&ctx).await.matched);
    }
}
