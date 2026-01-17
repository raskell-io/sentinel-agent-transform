//! Transform agent implementation.

use crate::config::TransformConfig;
use crate::context::{RequestInfo, ResponseInfo, TransformContext};
use crate::rule::{RuleEngine, RuleError};
use crate::transformer::TransformResult;
use async_trait::async_trait;
use sentinel_agent_protocol::v2::{
    AgentCapabilities, AgentFeatures, AgentHandlerV2, AgentLimits, CounterMetric, DrainReason,
    GaugeMetric, HealthStatus, MetricsReport, ShutdownReason,
};
use sentinel_agent_protocol::{
    AgentResponse, AuditMetadata, EventType, HeaderOp, RequestBodyChunkEvent,
    RequestHeadersEvent, ResponseBodyChunkEvent, ResponseHeadersEvent,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
    /// Whether the agent is draining (not accepting new requests).
    draining: AtomicBool,
    /// Metrics: total requests processed.
    requests_total: AtomicU64,
    /// Metrics: total requests transformed.
    requests_transformed: AtomicU64,
    /// Metrics: total transform errors.
    transform_errors: AtomicU64,
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
            draining: AtomicBool::new(false),
            requests_total: AtomicU64::new(0),
            requests_transformed: AtomicU64::new(0),
            transform_errors: AtomicU64::new(0),
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

    /// Build request info from request headers event.
    fn build_request_info(&self, event: &RequestHeadersEvent) -> RequestInfo {
        let headers: HashMap<String, Vec<String>> = event
            .headers
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.clone()))
            .collect();

        // Parse query string from path
        let full_path = &event.uri;
        let (path, query_string) = if let Some(pos) = full_path.find('?') {
            (
                full_path[..pos].to_string(),
                Some(full_path[pos + 1..].to_string()),
            )
        } else {
            (full_path.to_string(), None)
        };

        let query_params = parse_query_string(query_string.as_deref());

        RequestInfo {
            method: event.method.clone(),
            path,
            query_string,
            query_params,
            headers,
            client_ip: event.metadata.client_ip.clone(),
        }
    }

    /// Build response info from response headers event.
    fn build_response_info(&self, event: &ResponseHeadersEvent) -> ResponseInfo {
        use crate::context::status_text;

        let headers: HashMap<String, Vec<String>> = event
            .headers
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.clone()))
            .collect();

        let status = event.status;

        ResponseInfo {
            status,
            status_text: status_text(status),
            headers,
        }
    }

    /// Apply transform result to decision.
    fn apply_request_transforms(&self, result: TransformResult, rule_name: &str) -> AgentResponse {
        let mut response = AgentResponse::default_allow();

        // Add headers
        for (name, value) in result.add_headers {
            response = response.add_request_header(HeaderOp::Set { name, value });
        }

        // Remove headers
        for name in result.remove_headers {
            response = response.add_request_header(HeaderOp::Remove { name });
        }

        // URL rewriting (passed via routing metadata for proxy to use)
        if let Some(new_url) = result.new_url {
            response = response.add_request_header(HeaderOp::Set {
                name: "X-Original-Path".to_string(),
                value: new_url,
            });
        }

        // Add debug headers if enabled
        if self.config.settings.debug_headers {
            response = response.add_response_header(HeaderOp::Set {
                name: "X-Transform-Rule".to_string(),
                value: rule_name.to_string(),
            });
        }

        let audit = AuditMetadata {
            tags: vec!["transformed".to_string()],
            ..Default::default()
        };
        response.with_audit(audit)
    }

    /// Apply transform result to response decision.
    fn apply_response_transforms(
        &self,
        result: TransformResult,
        rule_name: &str,
        start_time: Instant,
    ) -> AgentResponse {
        let mut response = AgentResponse::default_allow();

        // Add response headers
        for (name, value) in result.add_headers {
            response = response.add_response_header(HeaderOp::Set { name, value });
        }

        // Remove response headers
        for name in result.remove_headers {
            response = response.add_response_header(HeaderOp::Remove { name });
        }

        // Add debug headers if enabled
        if self.config.settings.debug_headers {
            let duration = start_time.elapsed();
            response = response
                .add_response_header(HeaderOp::Set {
                    name: "X-Transform-Rule".to_string(),
                    value: rule_name.to_string(),
                })
                .add_response_header(HeaderOp::Set {
                    name: "X-Transform-Time".to_string(),
                    value: format!("{}ms", duration.as_millis()),
                });
        }

        response
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

    /// Check if agent is draining.
    fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }
}

/// Parse query string into parameter map.
fn parse_query_string(query: Option<&str>) -> HashMap<String, Vec<String>> {
    let mut params: HashMap<String, Vec<String>> = HashMap::new();

    if let Some(qs) = query {
        for part in qs.split('&') {
            if let Some((k, v)) = part.split_once('=') {
                let key = urlencoding::decode(k)
                    .unwrap_or_else(|_| k.into())
                    .to_string();
                let value = urlencoding::decode(v)
                    .unwrap_or_else(|_| v.into())
                    .to_string();
                params.entry(key).or_default().push(value);
            } else if !part.is_empty() {
                let key = urlencoding::decode(part)
                    .unwrap_or_else(|_| part.into())
                    .to_string();
                params.entry(key).or_default().push(String::new());
            }
        }
    }

    params
}

#[async_trait]
impl AgentHandlerV2 for TransformAgent {
    /// Return agent capabilities for v2 protocol.
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new(
            "transform",
            "Transform Agent",
            env!("CARGO_PKG_VERSION"),
        )
        .with_event(EventType::RequestHeaders)
        .with_event(EventType::RequestBodyChunk)
        .with_event(EventType::ResponseHeaders)
        .with_event(EventType::ResponseBodyChunk)
        .with_features(AgentFeatures {
            streaming_body: true,
            websocket: false,
            guardrails: false,
            config_push: true,
            metrics_export: true,
            concurrent_requests: 100,
            cancellation: true,
            flow_control: false,
            health_reporting: true,
        })
        .with_limits(AgentLimits {
            max_body_size: self.config.settings.max_body_size,
            max_concurrency: 100,
            preferred_chunk_size: 64 * 1024,
            max_memory: None,
            max_processing_time_ms: Some(self.config.settings.timeout_ms),
        })
    }

    /// Handle request headers event.
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        self.requests_total.fetch_add(1, Ordering::Relaxed);

        // Check if draining
        if self.is_draining() {
            debug!("Agent is draining, allowing request");
            return AgentResponse::default_allow();
        }

        let start_time = Instant::now();
        let correlation_id = &event.metadata.correlation_id;

        // Build context
        let request_info = self.build_request_info(&event);
        let ctx = TransformContext::new(request_info, correlation_id.to_string());

        // Find matching rule
        let (rule, captures) = match self.rule_engine.find_request_match(&ctx).await {
            Some((r, c)) => (r, c),
            None => {
                trace!(correlation_id, "No matching request transform rule");
                return AgentResponse::default_allow();
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
        let result = match rule.transform_request(&ctx, None).await {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    correlation_id,
                    rule = %rule.name,
                    error = %e,
                    "Request transformation failed"
                );
                self.transform_errors.fetch_add(1, Ordering::Relaxed);
                return AgentResponse::default_allow();
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
        let response = self.apply_request_transforms(result.clone(), &rule.name);

        self.requests_transformed.fetch_add(1, Ordering::Relaxed);

        info!(
            correlation_id,
            rule = %rule.name,
            has_url_rewrite = result.new_url.is_some(),
            headers_added = result.add_headers.len(),
            "Applied request transformations"
        );

        response
    }

    /// Handle request body chunk event.
    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        let correlation_id = &event.correlation_id;

        // Get stored context
        let stored = match self.get_context(correlation_id).await {
            Some(s) => s,
            None => return AgentResponse::default_allow(),
        };

        // Decode body from base64
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let body = match STANDARD.decode(&event.data) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "Failed to decode body from base64");
                // Re-store context for response phase
                self.store_context(
                    correlation_id,
                    StoredContext {
                        ctx: stored.ctx,
                        rule_name: stored.rule_name,
                        start_time: stored.start_time,
                    },
                )
                .await;
                return AgentResponse::default_allow();
            }
        };

        // Parse body as JSON if possible
        let ctx = if let Ok(json) = serde_json::from_slice(&body) {
            stored.ctx.with_body_json(json)
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
                return AgentResponse::default_allow();
            }
        };

        // Apply body transformations
        let result = match rule.transform_request(&ctx, Some(&body)).await {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    correlation_id,
                    rule = %rule.name,
                    error = %e,
                    "Request body transformation failed"
                );
                self.transform_errors.fetch_add(1, Ordering::Relaxed);
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
                return AgentResponse::default_allow();
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
        let response = AgentResponse::default_allow();

        if let Some(body) = result.body {
            // Note: Body mutation would need to be handled differently in v2
            // For now, we log and skip the body mutation
            debug!(
                correlation_id,
                rule = %rule.name,
                body_size = body.len(),
                "Request body transformation produced new body (mutation not supported in this version)"
            );
        }

        response
    }

    /// Handle response headers event.
    async fn on_response_headers(&self, event: ResponseHeadersEvent) -> AgentResponse {
        let correlation_id = &event.correlation_id;

        // Get stored context or create new one
        let stored = self.get_context(correlation_id).await;
        let (ctx, rule_name, start_time) = match stored {
            Some(s) => (s.ctx, s.rule_name, s.start_time),
            None => {
                // No stored context, create a minimal one
                return AgentResponse::default_allow();
            }
        };

        // Add response info to context
        let response_info = self.build_response_info(&event);
        let ctx = ctx.with_response(response_info);

        // Find matching response rule
        let (rule, captures) = match self.rule_engine.find_response_match(&ctx).await {
            Some((r, c)) => (r, c),
            None => {
                // No response transforms, but add debug headers if we have a rule name
                if self.config.settings.debug_headers {
                    if let Some(name) = rule_name {
                        return AgentResponse::default_allow()
                            .add_response_header(HeaderOp::Set {
                                name: "X-Transform-Rule".to_string(),
                                value: name,
                            })
                            .add_response_header(HeaderOp::Set {
                                name: "X-Transform-Time".to_string(),
                                value: format!("{}ms", start_time.elapsed().as_millis()),
                            });
                    }
                }
                return AgentResponse::default_allow();
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

        // Apply header transformations (body is handled in on_response_body_chunk)
        let result = match rule.transform_response(&ctx, None).await {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    correlation_id,
                    rule = %rule.name,
                    error = %e,
                    "Response transformation failed"
                );
                self.transform_errors.fetch_add(1, Ordering::Relaxed);
                return AgentResponse::default_allow();
            }
        };

        let response = self.apply_response_transforms(result, &rule.name, start_time);

        info!(
            correlation_id,
            rule = %rule.name,
            "Applied response transformations"
        );

        response
    }

    /// Handle response body chunk event.
    async fn on_response_body_chunk(&self, event: ResponseBodyChunkEvent) -> AgentResponse {
        let correlation_id = &event.correlation_id;

        // Get stored context
        let stored = match self.get_context(correlation_id).await {
            Some(s) => s,
            None => return AgentResponse::default_allow(),
        };

        let rule_name = match stored.rule_name {
            Some(ref name) => name.clone(),
            None => return AgentResponse::default_allow(),
        };

        // Decode body from base64
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let body = match STANDARD.decode(&event.data) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "Failed to decode response body from base64");
                return AgentResponse::default_allow();
            }
        };

        // Parse body as JSON if possible
        let ctx = if let Ok(json) = serde_json::from_slice(&body) {
            stored.ctx.with_body_json(json)
        } else {
            stored.ctx
        };

        // Find the rule again
        let (rule, _) = match self.rule_engine.find_response_match(&ctx).await {
            Some((r, c)) => (r, c),
            None => return AgentResponse::default_allow(),
        };

        // Apply body transformations
        let result = match rule.transform_response(&ctx, Some(&body)).await {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    correlation_id,
                    rule = %rule_name,
                    error = %e,
                    "Response body transformation failed"
                );
                self.transform_errors.fetch_add(1, Ordering::Relaxed);
                return AgentResponse::default_allow();
            }
        };

        // Build decision with body mutation
        let response = AgentResponse::default_allow();

        if let Some(body) = result.body {
            debug!(
                correlation_id,
                rule = %rule_name,
                body_size = body.len(),
                "Response body transformation produced new body (mutation not supported in this version)"
            );
        }

        response
    }

    /// Return current health status.
    fn health_status(&self) -> HealthStatus {
        let agent_id = "transform".to_string();

        if self.is_draining() {
            HealthStatus::degraded(agent_id, vec!["draining".to_string()], 1.5)
        } else {
            HealthStatus::healthy(agent_id)
        }
    }

    /// Return metrics report.
    fn metrics_report(&self) -> Option<MetricsReport> {
        let mut report = MetricsReport::new("transform", 10_000);

        report.counters.push(CounterMetric::new(
            "transform_requests_total",
            self.requests_total.load(Ordering::Relaxed),
        ));

        report.counters.push(CounterMetric::new(
            "transform_requests_transformed_total",
            self.requests_transformed.load(Ordering::Relaxed),
        ));

        report.counters.push(CounterMetric::new(
            "transform_errors_total",
            self.transform_errors.load(Ordering::Relaxed),
        ));

        // Current in-flight requests (contexts waiting)
        let contexts_count = {
            match self.request_contexts.try_read() {
                Ok(contexts) => contexts.len() as f64,
                Err(_) => 0.0,
            }
        };
        report.gauges.push(GaugeMetric::new(
            "transform_in_flight_requests",
            contexts_count,
        ));

        // Number of configured rules
        report.gauges.push(GaugeMetric::new(
            "transform_rules_count",
            self.rule_engine.rules().len() as f64,
        ));

        Some(report)
    }

    /// Handle configuration updates from proxy.
    async fn on_configure(&self, config: serde_json::Value, version: Option<String>) -> bool {
        info!(
            config_version = ?version,
            "Received configuration update"
        );

        // Log the configuration for debugging
        debug!(config = %config, "Configuration payload");

        // In a production implementation, you would parse and apply the new config
        // For now, we accept all configurations
        true
    }

    /// Handle shutdown request.
    async fn on_shutdown(&self, reason: ShutdownReason, grace_period_ms: u64) {
        info!(
            reason = ?reason,
            grace_period_ms = grace_period_ms,
            "Received shutdown request"
        );

        // Set draining to stop accepting new requests
        self.draining.store(true, Ordering::Relaxed);
    }

    /// Handle drain request.
    async fn on_drain(&self, duration_ms: u64, reason: DrainReason) {
        info!(
            duration_ms = duration_ms,
            reason = ?reason,
            "Received drain request"
        );

        // Set draining flag
        self.draining.store(true, Ordering::Relaxed);
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
            Some(&vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string()
            ])
        );
    }

    #[tokio::test]
    async fn test_agent_creation() {
        let config = TransformConfig::default();
        let agent = TransformAgent::new(config).unwrap();
        let caps = agent.capabilities();
        assert_eq!(caps.agent_id, "transform");
        assert_eq!(caps.name, "Transform Agent");
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
        let caps = agent.capabilities();
        assert_eq!(caps.agent_id, "transform");
        assert!(agent.config.settings.debug_headers);
    }

    #[test]
    fn test_capabilities() {
        let config = TransformConfig::default();
        let agent = TransformAgent::new(config).unwrap();
        let caps = agent.capabilities();

        assert_eq!(caps.agent_id, "transform");
        assert!(caps.supports_event(EventType::RequestHeaders));
        assert!(caps.supports_event(EventType::ResponseHeaders));
        assert!(caps.features.streaming_body);
        assert!(caps.features.metrics_export);
        assert!(caps.features.health_reporting);
    }

    #[test]
    fn test_health_status() {
        let config = TransformConfig::default();
        let agent = TransformAgent::new(config).unwrap();
        let health = agent.health_status();

        assert!(health.is_healthy());
        assert_eq!(health.agent_id, "transform");
    }

    #[test]
    fn test_metrics_report() {
        let config = TransformConfig::default();
        let agent = TransformAgent::new(config).unwrap();
        let report = agent.metrics_report();

        assert!(report.is_some());
        let report = report.unwrap();
        assert_eq!(report.agent_id, "transform");
        assert!(!report.counters.is_empty());
        assert!(!report.gauges.is_empty());
    }
}
