//! Header matching implementation.

use super::{MatchResult, Matcher, MatcherError};
use crate::config::HeaderMatcher;
use crate::context::TransformContext;
use async_trait::async_trait;
use regex::Regex;

/// Compiled header matcher.
pub struct HeaderMatcherImpl {
    /// Header name (lowercase)
    name: String,
    /// Match condition
    condition: HeaderCondition,
}

enum HeaderCondition {
    /// Exact value match
    Equals(String),
    /// Contains substring
    Contains(String),
    /// Regex match
    Matches(Regex),
    /// Header must be present
    Present,
    /// Header must be absent
    Absent,
}

impl HeaderMatcherImpl {
    /// Compile a header matcher from configuration.
    pub fn compile(config: &HeaderMatcher) -> Result<Self, MatcherError> {
        let name = config.name.to_lowercase();

        let condition = if let Some(ref value) = config.equals {
            HeaderCondition::Equals(value.clone())
        } else if let Some(ref substr) = config.contains {
            HeaderCondition::Contains(substr.clone())
        } else if let Some(ref pattern) = config.matches {
            HeaderCondition::Matches(Regex::new(pattern)?)
        } else if config.absent == Some(true) {
            HeaderCondition::Absent
        } else {
            // Default to presence check
            HeaderCondition::Present
        };

        Ok(Self { name, condition })
    }
}

#[async_trait]
impl Matcher for HeaderMatcherImpl {
    async fn matches(&self, ctx: &TransformContext) -> MatchResult {
        let header_value = ctx.request.headers
            .get(&self.name)
            .and_then(|v| v.first())
            .map(|s| s.as_str());

        let matched = match &self.condition {
            HeaderCondition::Equals(expected) => {
                header_value.is_some_and(|v| v == expected)
            }
            HeaderCondition::Contains(substr) => {
                header_value.is_some_and(|v| v.contains(substr))
            }
            HeaderCondition::Matches(regex) => {
                header_value.is_some_and(|v| regex.is_match(v))
            }
            HeaderCondition::Present => header_value.is_some(),
            HeaderCondition::Absent => header_value.is_none(),
        };

        if matched {
            MatchResult::matched()
        } else {
            MatchResult::not_matched()
        }
    }

    fn name(&self) -> &'static str {
        "header_matcher"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::RequestInfo;
    use std::collections::HashMap;

    fn make_context(headers: Vec<(&str, &str)>) -> TransformContext {
        let mut header_map = HashMap::new();
        for (k, v) in headers {
            header_map.insert(k.to_lowercase(), vec![v.to_string()]);
        }

        let request = RequestInfo {
            method: "GET".to_string(),
            path: "/test".to_string(),
            query_string: None,
            query_params: HashMap::new(),
            headers: header_map,
            client_ip: "127.0.0.1".to_string(),
        };
        TransformContext::new(request, "test".to_string())
    }

    #[tokio::test]
    async fn test_equals() {
        let config = HeaderMatcher {
            name: "Content-Type".to_string(),
            equals: Some("application/json".to_string()),
            contains: None,
            matches: None,
            present: None,
            absent: None,
        };
        let matcher = HeaderMatcherImpl::compile(&config).unwrap();

        let ctx = make_context(vec![("content-type", "application/json")]);
        assert!(matcher.matches(&ctx).await.matched);

        let ctx = make_context(vec![("content-type", "text/html")]);
        assert!(!matcher.matches(&ctx).await.matched);
    }

    #[tokio::test]
    async fn test_contains() {
        let config = HeaderMatcher {
            name: "Accept".to_string(),
            equals: None,
            contains: Some("json".to_string()),
            matches: None,
            present: None,
            absent: None,
        };
        let matcher = HeaderMatcherImpl::compile(&config).unwrap();

        let ctx = make_context(vec![("accept", "application/json, text/html")]);
        assert!(matcher.matches(&ctx).await.matched);

        let ctx = make_context(vec![("accept", "text/html")]);
        assert!(!matcher.matches(&ctx).await.matched);
    }

    #[tokio::test]
    async fn test_present() {
        let config = HeaderMatcher {
            name: "Authorization".to_string(),
            equals: None,
            contains: None,
            matches: None,
            present: Some(true),
            absent: None,
        };
        let matcher = HeaderMatcherImpl::compile(&config).unwrap();

        let ctx = make_context(vec![("authorization", "Bearer token")]);
        assert!(matcher.matches(&ctx).await.matched);

        let ctx = make_context(vec![]);
        assert!(!matcher.matches(&ctx).await.matched);
    }

    #[tokio::test]
    async fn test_absent() {
        let config = HeaderMatcher {
            name: "X-Debug".to_string(),
            equals: None,
            contains: None,
            matches: None,
            present: None,
            absent: Some(true),
        };
        let matcher = HeaderMatcherImpl::compile(&config).unwrap();

        let ctx = make_context(vec![]);
        assert!(matcher.matches(&ctx).await.matched);

        let ctx = make_context(vec![("x-debug", "true")]);
        assert!(!matcher.matches(&ctx).await.matched);
    }
}
