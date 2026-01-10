//! Transform agent implementation.

use crate::config::TransformConfig;
use crate::context::{RequestInfo, ResponseInfo, TransformContext};
use crate::rule::{RuleEngine, RuleError};
use crate::transformer::TransformResult;
use async_trait::async_trait;
use sentinel_agent_protocol::BodyMutation;
use sentinel_agent_sdk::{Agent, Decision, Request, Response};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, info, trace, warn};

/// Transform Agent for Sentinel.
///
/// Provides request and response transformations based on configurable rules.
pub struct TransformAgent {
    /// Configuration
    config: TransformConfig,
    /// Rule engine
    rule_engine: RuleEngine,
    /// Request contexts (keyed by correlation_id)
    /// Used to pass context from on_request to on_response
    request_contexts: Arc<RwLock<HashMap<String, StoredContext>>>,
}

/// Stored context for a request (used between phases).
struct StoredContext {
    /// Transform context with captures
    ctx: TransformContext,
    /// Applied rule name
    rule_name: Option<String>,
    /// Request start time
    start_time: Instant,
}

impl TransformAgent {
    /// Create a new transform agent from configuration.
    pub fn new(config: TransformConfig) -> Result<Self, RuleError> {
        let rule_engine = RuleEngine::new(&config)?;

        info!(
            rules = rule_engine.rules().len(),
            debug_headers = config.settings.debug_headers,
            "Transform agent initialized"
        );

        Ok(Self {
            config,
            rule_engine,
            request_contexts: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Create from a YAML configuration string.
    pub fn from_yaml(yaml: &str) -> Result<Self, TransformAgentError> {
        let config: TransformConfig = serde_yaml::from_str(yaml)?;
        Self::new(config).map_err(TransformAgentError::from)
    }

    /// Create from a JSON configuration string.
    pub fn from_json(json: &str) -> Result<Self, TransformAgentError> {
        let config: TransformConfig = serde_json::from_str(json)?;
        Self::new(config).map_err(TransformAgentError::from)
    }

    /// Build request info from SDK request.
    fn build_request_info(&self, request: &Request) -> RequestInfo {
        let headers: HashMap<String, Vec<String>> = request
            .headers()
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.clone()))
            .collect();

        // Parse query string from path
        let full_path = request.path();
        let (path, query_string) = if let Some(pos) = full_path.find('?') {
            (full_path[..pos].to_string(), Some(full_path[pos + 1..].to_string()))
        } else {
            (full_path.to_string(), None)
        };

        let query_params = parse_query_string(query_string.as_deref());

        RequestInfo {
            method: request.method().to_string(),
            path,
            query_string,
            query_params,
            headers,
            client_ip: request.client_ip().to_string(),
        }
    }

    /// Build response info from SDK response.
    fn build_response_info(&self, response: &Response) -> ResponseInfo {
        use crate::context::status_text;

        let headers: HashMap<String, Vec<String>> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.clone()))
            .collect();

        let status = response.status_code();

        ResponseInfo {
            status,
            status_text: status_text(status),
            headers,
        }
    }

    /// Apply transform result to decision.
    fn apply_request_transforms(&self, result: TransformResult, rule_name: &str) -> Decision {
        let mut decision = Decision::allow();

        // Add headers
        for (name, value) in result.add_headers {
            decision = decision.add_request_header(name, value);
        }

        // Remove headers
        for name in result.remove_headers {
            decision = decision.remove_request_header(name);
        }

        // URL rewriting (passed via routing metadata for proxy to use)
        if let Some(new_url) = result.new_url {
            decision = decision
                .with_routing_metadata("rewritten_path", new_url.clone())
                .add_request_header("X-Original-Path", new_url);
        }

        // Method override (passed via routing metadata)
        if let Some(new_method) = result.new_method {
            decision = decision.with_routing_metadata("rewritten_method", new_method);
        }

        // Add debug headers if enabled
        if self.config.settings.debug_headers {
            decision = decision.add_response_header("X-Transform-Rule", rule_name.to_string());
        }

        decision.with_tag("transformed")
    }

    /// Apply transform result to response decision.
    fn apply_response_transforms(
        &self,
        result: TransformResult,
        rule_name: &str,
        start_time: Instant,
    ) -> Decision {
        let mut decision = Decision::allow();

        // Add response headers
        for (name, value) in result.add_headers {
            decision = decision.add_response_header(name, value);
        }

        // Remove response headers
        for name in result.remove_headers {
            decision = decision.remove_response_header(name);
        }

        // Add debug headers if enabled
        if self.config.settings.debug_headers {
            let duration = start_time.elapsed();
            decision = decision
                .add_response_header("X-Transform-Rule", rule_name.to_string())
                .add_response_header("X-Transform-Time", format!("{}ms", duration.as_millis()));
        }

        decision
    }

    /// Store context for later phases.
    async fn store_context(&self, correlation_id: &str, ctx: StoredContext) {
        let mut contexts = self.request_contexts.write().await;
        contexts.insert(correlation_id.to_string(), ctx);

        // Cleanup old contexts (simple eviction if too many)
        if contexts.len() > 10000 {
            let old_keys: Vec<_> = contexts
                .iter()
                .filter(|(_, v)| v.start_time.elapsed().as_secs() > 60)
                .map(|(k, _)| k.clone())
                .collect();
            for key in old_keys {
                contexts.remove(&key);
            }
        }
    }

    /// Retrieve stored context.
    async fn get_context(&self, correlation_id: &str) -> Option<StoredContext> {
        let mut contexts = self.request_contexts.write().await;
        contexts.remove(correlation_id)
    }
}

/// Parse query string into parameter map.
fn parse_query_string(query: Option<&str>) -> HashMap<String, Vec<String>> {
    let mut params = HashMap::new();

    if let Some(qs) = query {
        for part in qs.split('&') {
            if let Some((k, v)) = part.split_once('=') {
                let key = urlencoding::decode(k).unwrap_or_else(|_| k.into()).to_string();
                let value = urlencoding::decode(v).unwrap_or_else(|_| v.into()).to_string();
                params.entry(key).or_insert_with(Vec::new).push(value);
            } else if !part.is_empty() {
                let key = urlencoding::decode(part)
                    .unwrap_or_else(|_| part.into())
                    .to_string();
                params.entry(key).or_insert_with(Vec::new).push(String::new());
            }
        }
    }

    params
}

#[async_trait]
impl Agent for TransformAgent {
    fn name(&self) -> &str {
        "transform"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        let start_time = Instant::now();
        let correlation_id = request.correlation_id();

        // Build context
        let request_info = self.build_request_info(request);
        let ctx = TransformContext::new(request_info, correlation_id.to_string());

        // Find matching rule
        let (rule, captures) = match self.rule_engine.find_request_match(&ctx).await {
            Some((r, c)) => (r, c),
            None => {
                trace!(correlation_id, "No matching request transform rule");
                return Decision::allow();
            }
        };

        debug!(
            correlation_id,
            rule = %rule.name,
            "Matched request transform rule"
        );

        // Update context with captures
        let ctx = ctx.with_captures(captures);

        // Apply transformations
        let result = match rule.transform_request(&ctx, request.body()).await {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    correlation_id,
                    rule = %rule.name,
                    error = %e,
                    "Request transformation failed"
                );
                return Decision::allow();
            }
        };

        // Store context for response phase
        self.store_context(
            correlation_id,
            StoredContext {
                ctx,
                rule_name: Some(rule.name.clone()),
                start_time,
            },
        )
        .await;

        // Build decision
        let mut decision = self.apply_request_transforms(result.clone(), &rule.name);

        // Handle body transformation
        if let Some(body) = result.body {
            decision = decision.with_request_body_mutation(BodyMutation::replace(
                0,
                String::from_utf8_lossy(&body).to_string(),
            ));
        }

        info!(
            correlation_id,
            rule = %rule.name,
            has_url_rewrite = result.new_url.is_some(),
            headers_added = result.add_headers.len(),
            "Applied request transformations"
        );

        decision
    }

    async fn on_request_body(&self, request: &Request) -> Decision {
        let correlation_id = request.correlation_id();

        // Get stored context
        let stored = match self.get_context(correlation_id).await {
            Some(s) => s,
            None => return Decision::allow(),
        };

        // Parse body as JSON if possible
        let ctx = if let Some(body) = request.body() {
            if let Ok(json) = serde_json::from_slice(body) {
                stored.ctx.with_body_json(json)
            } else {
                stored.ctx
            }
        } else {
            stored.ctx
        };

        // Find matching rule again (now with body context)
        let (rule, _) = match self.rule_engine.find_request_match(&ctx).await {
            Some((r, c)) => (r, c),
            None => {
                // Re-store context for response phase
                self.store_context(
                    correlation_id,
                    StoredContext {
                        ctx,
                        rule_name: stored.rule_name,
                        start_time: stored.start_time,
                    },
                )
                .await;
                return Decision::allow();
            }
        };

        // Apply body transformations
        let result = match rule.transform_request(&ctx, request.body()).await {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    correlation_id,
                    rule = %rule.name,
                    error = %e,
                    "Request body transformation failed"
                );
                // Re-store context for response phase
                self.store_context(
                    correlation_id,
                    StoredContext {
                        ctx,
                        rule_name: Some(rule.name.clone()),
                        start_time: stored.start_time,
                    },
                )
                .await;
                return Decision::allow();
            }
        };

        // Re-store context for response phase
        self.store_context(
            correlation_id,
            StoredContext {
                ctx,
                rule_name: Some(rule.name.clone()),
                start_time: stored.start_time,
            },
        )
        .await;

        // Build decision with body mutation
        let mut decision = Decision::allow();

        if let Some(body) = result.body {
            decision = decision.with_request_body_mutation(BodyMutation::replace(
                0,
                String::from_utf8_lossy(&body).to_string(),
            ));
            debug!(
                correlation_id,
                rule = %rule.name,
                "Applied request body transformation"
            );
        }

        decision
    }

    async fn on_response(&self, request: &Request, response: &Response) -> Decision {
        let correlation_id = request.correlation_id();

        // Get stored context or create new one
        let stored = self.get_context(correlation_id).await;
        let (ctx, rule_name, start_time) = match stored {
            Some(s) => (s.ctx, s.rule_name, s.start_time),
            None => {
                let request_info = self.build_request_info(request);
                (
                    TransformContext::new(request_info, correlation_id.to_string()),
                    None,
                    Instant::now(),
                )
            }
        };

        // Add response info to context
        let response_info = self.build_response_info(response);
        let ctx = ctx.with_response(response_info);

        // Find matching response rule
        let (rule, captures) = match self.rule_engine.find_response_match(&ctx).await {
            Some((r, c)) => (r, c),
            None => {
                // No response transforms, but add debug headers if we have a rule name
                if self.config.settings.debug_headers {
                    if let Some(name) = rule_name {
                        return Decision::allow()
                            .add_response_header("X-Transform-Rule", name)
                            .add_response_header(
                                "X-Transform-Time",
                                format!("{}ms", start_time.elapsed().as_millis()),
                            );
                    }
                }
                return Decision::allow();
            }
        };

        debug!(
            correlation_id,
            rule = %rule.name,
            "Matched response transform rule"
        );

        // Update context with captures
        let ctx = ctx.with_captures(captures);

        // Store for potential body phase
        self.store_context(
            correlation_id,
            StoredContext {
                ctx: ctx.clone(),
                rule_name: Some(rule.name.clone()),
                start_time,
            },
        )
        .await;

        // Apply header transformations (body is handled in on_response_body)
        let result = match rule.transform_response(&ctx, None).await {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    correlation_id,
                    rule = %rule.name,
                    error = %e,
                    "Response transformation failed"
                );
                return Decision::allow();
            }
        };

        let decision = self.apply_response_transforms(result, &rule.name, start_time);

        info!(
            correlation_id,
            rule = %rule.name,
            "Applied response transformations"
        );

        decision
    }

    async fn on_response_body(&self, request: &Request, response: &Response) -> Decision {
        let correlation_id = request.correlation_id();

        // Get stored context
        let stored = match self.get_context(correlation_id).await {
            Some(s) => s,
            None => return Decision::allow(),
        };

        let rule_name = match stored.rule_name {
            Some(ref name) => name.clone(),
            None => return Decision::allow(),
        };

        // Parse body as JSON if possible
        let ctx = if let Some(body) = response.body() {
            if let Ok(json) = serde_json::from_slice(body) {
                stored.ctx.with_body_json(json)
            } else {
                stored.ctx
            }
        } else {
            stored.ctx
        };

        // Find the rule again
        let (rule, _) = match self.rule_engine.find_response_match(&ctx).await {
            Some((r, c)) => (r, c),
            None => return Decision::allow(),
        };

        // Apply body transformations
        let result = match rule.transform_response(&ctx, response.body()).await {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    correlation_id,
                    rule = %rule_name,
                    error = %e,
                    "Response body transformation failed"
                );
                return Decision::allow();
            }
        };

        // Build decision with body mutation
        let mut decision = Decision::allow();

        if let Some(body) = result.body {
            decision = decision.with_response_body_mutation(BodyMutation::replace(
                0,
                String::from_utf8_lossy(&body).to_string(),
            ));
            debug!(
                correlation_id,
                rule = %rule_name,
                "Applied response body transformation"
            );
        }

        decision
    }
}

/// Transform agent errors.
#[derive(Debug, thiserror::Error)]
pub enum TransformAgentError {
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Rule error: {0}")]
    Rule(#[from] RuleError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_query_string() {
        let params = parse_query_string(Some("foo=bar&baz=qux"));
        assert_eq!(params.get("foo"), Some(&vec!["bar".to_string()]));
        assert_eq!(params.get("baz"), Some(&vec!["qux".to_string()]));
    }

    #[test]
    fn test_parse_query_string_encoded() {
        let params = parse_query_string(Some("name=hello%20world"));
        assert_eq!(params.get("name"), Some(&vec!["hello world".to_string()]));
    }

    #[test]
    fn test_parse_query_string_multiple() {
        let params = parse_query_string(Some("tags=a&tags=b&tags=c"));
        assert_eq!(
            params.get("tags"),
            Some(&vec!["a".to_string(), "b".to_string(), "c".to_string()])
        );
    }

    #[tokio::test]
    async fn test_agent_creation() {
        let config = TransformConfig::default();
        let agent = TransformAgent::new(config).unwrap();
        assert_eq!(agent.name(), "transform");
    }

    #[tokio::test]
    async fn test_agent_from_yaml() {
        let yaml = r#"
version: "1"
settings:
  debug_headers: true
rules: []
"#;
        let agent = TransformAgent::from_yaml(yaml).unwrap();
        assert_eq!(agent.name(), "transform");
        assert!(agent.config.settings.debug_headers);
    }
}
