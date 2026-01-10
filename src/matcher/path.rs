//! Path matching implementation.

use super::{MatchResult, Matcher, MatcherError};
use crate::config::{PathMatcher, PatternType};
use crate::context::TransformContext;
use async_trait::async_trait;
use glob::Pattern as GlobPattern;
use regex::Regex;
use std::collections::HashMap;

/// Compiled path matcher.
pub enum PathMatcherImpl {
    /// Exact string match
    Exact(String),
    /// Glob pattern match
    Glob(GlobPattern),
    /// Regex pattern match
    Regex(Regex),
}

impl PathMatcherImpl {
    /// Compile a path matcher from configuration.
    pub fn compile(config: &PathMatcher) -> Result<Self, MatcherError> {
        match config.pattern_type {
            PatternType::Exact => Ok(Self::Exact(config.pattern.clone())),
            PatternType::Glob => {
                let pattern = GlobPattern::new(&config.pattern)?;
                Ok(Self::Glob(pattern))
            }
            PatternType::Regex => {
                let regex = Regex::new(&config.pattern)?;
                Ok(Self::Regex(regex))
            }
        }
    }

    /// Extract captures from a regex match.
    fn extract_captures(regex: &Regex, text: &str) -> HashMap<String, String> {
        let mut captures = HashMap::new();

        if let Some(caps) = regex.captures(text) {
            // Add numbered captures
            for (i, m) in caps.iter().enumerate() {
                if let Some(m) = m {
                    captures.insert(i.to_string(), m.as_str().to_string());
                }
            }

            // Add named captures
            for name in regex.capture_names().flatten() {
                if let Some(m) = caps.name(name) {
                    captures.insert(name.to_string(), m.as_str().to_string());
                }
            }
        }

        captures
    }
}

#[async_trait]
impl Matcher for PathMatcherImpl {
    async fn matches(&self, ctx: &TransformContext) -> MatchResult {
        let path = &ctx.request.path;

        match self {
            Self::Exact(pattern) => {
                if path == pattern {
                    MatchResult::matched()
                } else {
                    MatchResult::not_matched()
                }
            }
            Self::Glob(pattern) => {
                if pattern.matches(path) {
                    MatchResult::matched()
                } else {
                    MatchResult::not_matched()
                }
            }
            Self::Regex(regex) => {
                if regex.is_match(path) {
                    let captures = Self::extract_captures(regex, path);
                    MatchResult::matched_with_captures(captures)
                } else {
                    MatchResult::not_matched()
                }
            }
        }
    }

    fn name(&self) -> &'static str {
        "path_matcher"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::RequestInfo;

    fn make_context(path: &str) -> TransformContext {
        let request = RequestInfo {
            method: "GET".to_string(),
            path: path.to_string(),
            query_string: None,
            query_params: HashMap::new(),
            headers: HashMap::new(),
            client_ip: "127.0.0.1".to_string(),
        };
        TransformContext::new(request, "test".to_string())
    }

    #[tokio::test]
    async fn test_exact_match() {
        let config = PathMatcher {
            pattern: "/api/users".to_string(),
            pattern_type: PatternType::Exact,
        };
        let matcher = PathMatcherImpl::compile(&config).unwrap();

        let ctx = make_context("/api/users");
        assert!(matcher.matches(&ctx).await.matched);

        let ctx = make_context("/api/users/123");
        assert!(!matcher.matches(&ctx).await.matched);
    }

    #[tokio::test]
    async fn test_glob_match() {
        let config = PathMatcher {
            pattern: "/api/*/items".to_string(),
            pattern_type: PatternType::Glob,
        };
        let matcher = PathMatcherImpl::compile(&config).unwrap();

        let ctx = make_context("/api/users/items");
        assert!(matcher.matches(&ctx).await.matched);

        let ctx = make_context("/api/orders/items");
        assert!(matcher.matches(&ctx).await.matched);

        let ctx = make_context("/api/users");
        assert!(!matcher.matches(&ctx).await.matched);
    }

    #[tokio::test]
    async fn test_regex_match_with_captures() {
        let config = PathMatcher {
            pattern: r"^/api/v1/(?P<resource>\w+)/(?P<id>\d+)$".to_string(),
            pattern_type: PatternType::Regex,
        };
        let matcher = PathMatcherImpl::compile(&config).unwrap();

        let ctx = make_context("/api/v1/users/123");
        let result = matcher.matches(&ctx).await;
        assert!(result.matched);
        assert_eq!(result.captures.get("resource"), Some(&"users".to_string()));
        assert_eq!(result.captures.get("id"), Some(&"123".to_string()));
        assert_eq!(result.captures.get("0"), Some(&"/api/v1/users/123".to_string()));
    }

    #[tokio::test]
    async fn test_regex_no_match() {
        let config = PathMatcher {
            pattern: r"^/api/v2/.*$".to_string(),
            pattern_type: PatternType::Regex,
        };
        let matcher = PathMatcherImpl::compile(&config).unwrap();

        let ctx = make_context("/api/v1/users");
        assert!(!matcher.matches(&ctx).await.matched);
    }
}
