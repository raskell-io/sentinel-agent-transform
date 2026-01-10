//! Rule compilation and evaluation.

use crate::config::{Rule, TransformConfig};
use crate::context::TransformContext;
use crate::matcher::{CompiledMatcher, MatcherError};
use crate::transformer::{
    HeaderTransformer, JsonTransformer, TransformError, TransformResult, TransformerChain,
    UrlTransformer,
};
use tracing::{debug, trace};

/// A compiled rule ready for evaluation.
pub struct CompiledRule {
    /// Rule name
    pub name: String,
    /// Rule priority (higher = evaluated first)
    pub priority: i32,
    /// Compiled matcher
    matcher: CompiledMatcher,
    /// Request transformers
    request_transformers: TransformerChain,
    /// Response transformers
    response_transformers: TransformerChain,
    /// Method override (if any)
    method_override: Option<String>,
    /// Status override (if any)
    status_override: Option<u16>,
}

impl CompiledRule {
    /// Compile a rule from configuration.
    pub fn compile(rule: &Rule) -> Result<Self, RuleError> {
        if !rule.enabled {
            return Err(RuleError::Disabled(rule.name.clone()));
        }

        // Compile matcher
        let matcher = CompiledMatcher::compile(&rule.matcher)?;

        // Build request transformers
        let mut request_transformers = TransformerChain::new();
        let mut method_override = None;

        if let Some(ref request) = rule.request {
            // URL transformer
            if let Some(ref url_config) = request.url {
                request_transformers = request_transformers.add(UrlTransformer::new(url_config));
            }

            // Header transformer
            if let Some(ref header_config) = request.headers {
                request_transformers =
                    request_transformers.add(HeaderTransformer::new(header_config));
            }

            // Body transformer
            if let Some(ref body_config) = request.body {
                if let Some(ref json_config) = body_config.json {
                    request_transformers =
                        request_transformers.add(JsonTransformer::new(json_config));
                }
            }

            // Method override
            method_override = request.method.clone();
        }

        // Build response transformers
        let mut response_transformers = TransformerChain::new();
        let mut status_override = None;

        if let Some(ref response) = rule.response {
            // Header transformer
            if let Some(ref header_config) = response.headers {
                response_transformers =
                    response_transformers.add(HeaderTransformer::new(header_config));
            }

            // Body transformer
            if let Some(ref body_config) = response.body {
                if let Some(ref json_config) = body_config.json {
                    response_transformers =
                        response_transformers.add(JsonTransformer::new(json_config));
                }
            }

            // Status override
            status_override = response.status;
        }

        Ok(Self {
            name: rule.name.clone(),
            priority: rule.priority,
            matcher,
            request_transformers,
            response_transformers,
            method_override,
            status_override,
        })
    }

    /// Check if this rule matches the given context.
    pub async fn matches(&self, ctx: &TransformContext) -> bool {
        let result = self.matcher.matches(ctx).await;
        result.matched
    }

    /// Check if this rule matches and return captures.
    pub async fn matches_with_captures(
        &self,
        ctx: &TransformContext,
    ) -> Option<std::collections::HashMap<String, String>> {
        let result = self.matcher.matches(ctx).await;
        if result.matched {
            Some(result.captures)
        } else {
            None
        }
    }

    /// Apply request transformations.
    pub async fn transform_request(
        &self,
        ctx: &TransformContext,
        body: Option<&[u8]>,
    ) -> Result<TransformResult, TransformError> {
        let mut result = self.request_transformers.apply(ctx, body).await?;

        // Apply method override
        if let Some(ref method) = self.method_override {
            result = result.set_method(ctx.interpolate(method));
        }

        Ok(result)
    }

    /// Apply response transformations.
    pub async fn transform_response(
        &self,
        ctx: &TransformContext,
        body: Option<&[u8]>,
    ) -> Result<TransformResult, TransformError> {
        let mut result = self.response_transformers.apply(ctx, body).await?;

        // Apply status override
        if let Some(status) = self.status_override {
            result = result.set_status(status);
        }

        Ok(result)
    }

    /// Check if this rule has request transforms.
    pub fn has_request_transforms(&self) -> bool {
        !self.request_transformers.is_empty() || self.method_override.is_some()
    }

    /// Check if this rule has response transforms.
    pub fn has_response_transforms(&self) -> bool {
        !self.response_transformers.is_empty() || self.status_override.is_some()
    }
}

/// Rule engine that manages compiled rules.
pub struct RuleEngine {
    /// Compiled rules sorted by priority (highest first)
    rules: Vec<CompiledRule>,
}

impl RuleEngine {
    /// Create a new rule engine from configuration.
    pub fn new(config: &TransformConfig) -> Result<Self, RuleError> {
        let mut rules = Vec::new();

        for rule in &config.rules {
            match CompiledRule::compile(rule) {
                Ok(compiled) => {
                    debug!(rule = %compiled.name, priority = compiled.priority, "Compiled rule");
                    rules.push(compiled);
                }
                Err(RuleError::Disabled(name)) => {
                    debug!(rule = %name, "Skipping disabled rule");
                }
                Err(e) => return Err(e),
            }
        }

        // Sort by priority (highest first)
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        debug!(count = rules.len(), "Rule engine initialized");

        Ok(Self { rules })
    }

    /// Find the first matching rule for request phase.
    pub async fn find_request_match<'a>(
        &'a self,
        ctx: &TransformContext,
    ) -> Option<(&'a CompiledRule, std::collections::HashMap<String, String>)> {
        for rule in &self.rules {
            if !rule.has_request_transforms() {
                continue;
            }

            if let Some(captures) = rule.matches_with_captures(ctx).await {
                trace!(rule = %rule.name, "Request matched rule");
                return Some((rule, captures));
            }
        }
        None
    }

    /// Find the first matching rule for response phase.
    pub async fn find_response_match<'a>(
        &'a self,
        ctx: &TransformContext,
    ) -> Option<(&'a CompiledRule, std::collections::HashMap<String, String>)> {
        for rule in &self.rules {
            if !rule.has_response_transforms() {
                continue;
            }

            if let Some(captures) = rule.matches_with_captures(ctx).await {
                trace!(rule = %rule.name, "Response matched rule");
                return Some((rule, captures));
            }
        }
        None
    }

    /// Get all rules.
    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    /// Check if the engine has any rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Errors during rule compilation.
#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    #[error("Rule '{0}' is disabled")]
    Disabled(String),

    #[error("Matcher error: {0}")]
    Matcher(#[from] MatcherError),

    #[error("Invalid rule configuration: {0}")]
    InvalidConfig(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;
    use crate::context::RequestInfo;
    use std::collections::HashMap;

    fn make_context(method: &str, path: &str) -> TransformContext {
        let request = RequestInfo {
            method: method.to_string(),
            path: path.to_string(),
            query_string: None,
            query_params: HashMap::new(),
            headers: HashMap::new(),
            client_ip: "127.0.0.1".to_string(),
        };
        TransformContext::new(request, "test".to_string())
    }

    #[tokio::test]
    async fn test_rule_matching() {
        let rule = Rule {
            name: "test-rule".to_string(),
            description: String::new(),
            enabled: true,
            priority: 100,
            matcher: RuleMatcher {
                path: Some(PathMatcher {
                    pattern: "^/api/.*$".to_string(),
                    pattern_type: PatternType::Regex,
                }),
                methods: Some(vec!["GET".to_string()]),
                ..Default::default()
            },
            request: Some(RequestTransform {
                url: Some(UrlTransform {
                    rewrite: "/v2/api".to_string(),
                    preserve_query: true,
                    add_query: None,
                    remove_query: None,
                }),
                ..Default::default()
            }),
            response: None,
        };

        let compiled = CompiledRule::compile(&rule).unwrap();

        let ctx = make_context("GET", "/api/users");
        assert!(compiled.matches(&ctx).await);

        let ctx = make_context("POST", "/api/users");
        assert!(!compiled.matches(&ctx).await);

        let ctx = make_context("GET", "/other/path");
        assert!(!compiled.matches(&ctx).await);
    }

    #[tokio::test]
    async fn test_rule_priority() {
        let config = TransformConfig {
            version: "1".to_string(),
            settings: Settings::default(),
            rules: vec![
                Rule {
                    name: "low-priority".to_string(),
                    description: String::new(),
                    enabled: true,
                    priority: 10,
                    matcher: RuleMatcher {
                        path: Some(PathMatcher {
                            pattern: "^/api/.*$".to_string(),
                            pattern_type: PatternType::Regex,
                        }),
                        ..Default::default()
                    },
                    request: Some(RequestTransform {
                        url: Some(UrlTransform {
                            rewrite: "/low".to_string(),
                            preserve_query: true,
                            add_query: None,
                            remove_query: None,
                        }),
                        ..Default::default()
                    }),
                    response: None,
                },
                Rule {
                    name: "high-priority".to_string(),
                    description: String::new(),
                    enabled: true,
                    priority: 100,
                    matcher: RuleMatcher {
                        path: Some(PathMatcher {
                            pattern: "^/api/.*$".to_string(),
                            pattern_type: PatternType::Regex,
                        }),
                        ..Default::default()
                    },
                    request: Some(RequestTransform {
                        url: Some(UrlTransform {
                            rewrite: "/high".to_string(),
                            preserve_query: true,
                            add_query: None,
                            remove_query: None,
                        }),
                        ..Default::default()
                    }),
                    response: None,
                },
            ],
        };

        let engine = RuleEngine::new(&config).unwrap();

        // High priority should be first
        assert_eq!(engine.rules[0].name, "high-priority");
        assert_eq!(engine.rules[1].name, "low-priority");

        // Should match high priority first
        let ctx = make_context("GET", "/api/test");
        let (matched_rule, _) = engine.find_request_match(&ctx).await.unwrap();
        assert_eq!(matched_rule.name, "high-priority");
    }

    #[tokio::test]
    async fn test_request_transform() {
        let rule = Rule {
            name: "transform-test".to_string(),
            description: String::new(),
            enabled: true,
            priority: 100,
            matcher: RuleMatcher {
                path: Some(PathMatcher {
                    pattern: "^/api/v1/(?P<resource>\\w+)/(?P<id>\\d+)$".to_string(),
                    pattern_type: PatternType::Regex,
                }),
                ..Default::default()
            },
            request: Some(RequestTransform {
                url: Some(UrlTransform {
                    rewrite: "/api/v2/${resource}/${id}".to_string(),
                    preserve_query: false,
                    add_query: None,
                    remove_query: None,
                }),
                headers: Some(HeaderTransform {
                    add: Some(vec![HeaderValue {
                        name: "X-Version".to_string(),
                        value: "2".to_string(),
                    }]),
                    set: None,
                    remove: None,
                }),
                ..Default::default()
            }),
            response: None,
        };

        let compiled = CompiledRule::compile(&rule).unwrap();

        let ctx = make_context("GET", "/api/v1/users/123");
        let captures = compiled.matches_with_captures(&ctx).await.unwrap();

        let ctx = ctx.with_captures(captures);
        let result = compiled.transform_request(&ctx, None).await.unwrap();

        assert_eq!(result.new_url, Some("/api/v2/users/123".to_string()));
        assert_eq!(result.add_headers.len(), 1);
        assert_eq!(
            result.add_headers[0],
            ("X-Version".to_string(), "2".to_string())
        );
    }

    #[tokio::test]
    async fn test_disabled_rule() {
        let rule = Rule {
            name: "disabled-rule".to_string(),
            description: String::new(),
            enabled: false,
            priority: 100,
            matcher: RuleMatcher::default(),
            request: None,
            response: None,
        };

        let result = CompiledRule::compile(&rule);
        assert!(matches!(result, Err(RuleError::Disabled(_))));
    }
}
