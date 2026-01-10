//! Request and response matchers.

mod path;
mod header;
mod body;

pub use path::PathMatcherImpl;
pub use header::HeaderMatcherImpl;
pub use body::BodyMatcherImpl;

use crate::config::{RuleMatcher, ResponseMatcher};
use crate::context::TransformContext;
use async_trait::async_trait;
use std::collections::HashMap;

/// Trait for matching requests or responses.
#[async_trait]
pub trait Matcher: Send + Sync {
    /// Check if this matcher matches the given context.
    async fn matches(&self, ctx: &TransformContext) -> MatchResult;

    /// Get the matcher name for debugging.
    fn name(&self) -> &'static str;
}

/// Result of a match operation.
#[derive(Debug, Clone)]
pub struct MatchResult {
    /// Whether the match succeeded
    pub matched: bool,
    /// Captured groups (from regex matching)
    pub captures: HashMap<String, String>,
}

impl MatchResult {
    /// Create a successful match result.
    pub fn matched() -> Self {
        Self {
            matched: true,
            captures: HashMap::new(),
        }
    }

    /// Create a successful match result with captures.
    pub fn matched_with_captures(captures: HashMap<String, String>) -> Self {
        Self {
            matched: true,
            captures,
        }
    }

    /// Create a failed match result.
    pub fn not_matched() -> Self {
        Self {
            matched: false,
            captures: HashMap::new(),
        }
    }
}

/// Compiled rule matcher that combines all conditions.
pub struct CompiledMatcher {
    /// Path matcher
    path: Option<PathMatcherImpl>,
    /// Allowed methods
    methods: Option<Vec<String>>,
    /// Header matchers
    headers: Vec<HeaderMatcherImpl>,
    /// Body matcher
    body: Option<BodyMatcherImpl>,
    /// Response matcher (for response-phase rules)
    response: Option<CompiledResponseMatcher>,
}

/// Compiled response matcher.
pub struct CompiledResponseMatcher {
    status_codes: Option<Vec<u16>>,
    content_types: Option<Vec<String>>,
}

impl CompiledMatcher {
    /// Compile a rule matcher from configuration.
    pub fn compile(config: &RuleMatcher) -> Result<Self, MatcherError> {
        let path = config.path.as_ref()
            .map(|p| PathMatcherImpl::compile(p))
            .transpose()?;

        let methods = config.methods.clone();

        let headers = config.headers.as_ref()
            .map(|hs| hs.iter().map(HeaderMatcherImpl::compile).collect::<Result<Vec<_>, _>>())
            .transpose()?
            .unwrap_or_default();

        let body = config.body.as_ref()
            .map(|b| BodyMatcherImpl::compile(b))
            .transpose()?;

        let response = config.response.as_ref()
            .map(CompiledResponseMatcher::compile);

        Ok(Self {
            path,
            methods,
            headers,
            body,
            response,
        })
    }

    /// Check if the request matches all conditions.
    pub async fn matches_request(&self, ctx: &TransformContext) -> MatchResult {
        let mut all_captures = HashMap::new();

        // Check path
        if let Some(ref path_matcher) = self.path {
            let result = path_matcher.matches(ctx).await;
            if !result.matched {
                return MatchResult::not_matched();
            }
            all_captures.extend(result.captures);
        }

        // Check methods
        if let Some(ref methods) = self.methods {
            let method = ctx.request.method.to_uppercase();
            if !methods.iter().any(|m| m.to_uppercase() == method) {
                return MatchResult::not_matched();
            }
        }

        // Check headers
        for header_matcher in &self.headers {
            let result = header_matcher.matches(ctx).await;
            if !result.matched {
                return MatchResult::not_matched();
            }
        }

        // Check body (only if we have body JSON)
        if let Some(ref body_matcher) = self.body {
            if ctx.body_json.is_some() {
                let result = body_matcher.matches(ctx).await;
                if !result.matched {
                    return MatchResult::not_matched();
                }
            }
        }

        MatchResult::matched_with_captures(all_captures)
    }

    /// Check if the response matches all conditions.
    pub async fn matches_response(&self, ctx: &TransformContext) -> MatchResult {
        // First check request conditions
        let request_result = self.matches_request(ctx).await;
        if !request_result.matched {
            return request_result;
        }

        // Then check response conditions
        if let Some(ref response_matcher) = self.response {
            if let Some(ref response) = ctx.response {
                // Check status codes
                if let Some(ref status_codes) = response_matcher.status_codes {
                    if !status_codes.contains(&response.status) {
                        return MatchResult::not_matched();
                    }
                }

                // Check content types
                if let Some(ref content_types) = response_matcher.content_types {
                    let ct = response.header("content-type").unwrap_or("");
                    if !content_types.iter().any(|t| ct.contains(t)) {
                        return MatchResult::not_matched();
                    }
                }
            } else {
                // Response matcher present but no response - doesn't match
                return MatchResult::not_matched();
            }
        }

        request_result
    }

    /// Check if this matcher has response conditions.
    pub fn has_response_conditions(&self) -> bool {
        self.response.is_some()
    }

    /// General match method - delegates to matches_request.
    pub async fn matches(&self, ctx: &TransformContext) -> MatchResult {
        self.matches_request(ctx).await
    }
}

impl CompiledResponseMatcher {
    fn compile(config: &ResponseMatcher) -> Self {
        Self {
            status_codes: config.status_codes.clone(),
            content_types: config.content_types.clone(),
        }
    }
}

/// Errors that can occur during matcher compilation.
#[derive(Debug, thiserror::Error)]
pub enum MatcherError {
    #[error("Invalid regex pattern: {0}")]
    InvalidRegex(#[from] regex::Error),

    #[error("Invalid glob pattern: {0}")]
    InvalidGlob(#[from] glob::PatternError),

    #[error("Invalid JSON path: {0}")]
    InvalidJsonPath(String),
}
