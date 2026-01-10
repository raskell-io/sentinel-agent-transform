//! URL rewriting transformer.

use super::{TransformError, TransformResult, Transformer};
use crate::config::UrlTransform;
use crate::context::TransformContext;
use async_trait::async_trait;
use std::collections::HashMap;

/// URL rewriting transformer.
pub struct UrlTransformer {
    /// Rewrite pattern with variable placeholders
    rewrite_pattern: String,
    /// Whether to preserve the original query string
    preserve_query: bool,
    /// Query parameters to add
    add_query: HashMap<String, String>,
    /// Query parameters to remove
    remove_query: Vec<String>,
}

impl UrlTransformer {
    /// Create a new URL transformer from configuration.
    pub fn new(config: &UrlTransform) -> Self {
        Self {
            rewrite_pattern: config.rewrite.clone(),
            preserve_query: config.preserve_query,
            add_query: config.add_query.clone().unwrap_or_default(),
            remove_query: config.remove_query.clone().unwrap_or_default(),
        }
    }
}

#[async_trait]
impl Transformer for UrlTransformer {
    async fn transform(
        &self,
        ctx: &TransformContext,
        _body: Option<&[u8]>,
    ) -> Result<TransformResult, TransformError> {
        // Interpolate variables in rewrite pattern
        let mut new_path = ctx.interpolate(&self.rewrite_pattern);

        // Build query string
        let mut query_parts: Vec<(String, String)> = Vec::new();

        // Preserve original query parameters if configured
        if self.preserve_query {
            for (key, values) in &ctx.request.query_params {
                // Skip if in remove list
                if self.remove_query.contains(key) {
                    continue;
                }
                for value in values {
                    query_parts.push((key.clone(), value.clone()));
                }
            }
        }

        // Add configured query parameters (with variable interpolation)
        for (key, value) in &self.add_query {
            let interpolated_value = ctx.interpolate(value);
            query_parts.push((key.clone(), interpolated_value));
        }

        // Append query string if present
        if !query_parts.is_empty() {
            let query_string: String = query_parts
                .iter()
                .map(|(k, v)| {
                    format!(
                        "{}={}",
                        urlencoding::encode(k),
                        urlencoding::encode(v)
                    )
                })
                .collect::<Vec<_>>()
                .join("&");
            new_path = format!("{}?{}", new_path, query_string);
        }

        Ok(TransformResult::with_url(new_path))
    }

    fn name(&self) -> &'static str {
        "url_transformer"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::RequestInfo;

    fn make_context(path: &str, query: Option<&str>) -> TransformContext {
        let mut query_params = HashMap::new();
        if let Some(qs) = query {
            for part in qs.split('&') {
                if let Some((k, v)) = part.split_once('=') {
                    query_params.entry(k.to_string())
                        .or_insert_with(Vec::new)
                        .push(v.to_string());
                }
            }
        }

        let request = RequestInfo {
            method: "GET".to_string(),
            path: path.to_string(),
            query_string: query.map(|s| s.to_string()),
            query_params,
            headers: HashMap::new(),
            client_ip: "127.0.0.1".to_string(),
        };

        let mut captures = HashMap::new();
        captures.insert("resource".to_string(), "users".to_string());
        captures.insert("id".to_string(), "123".to_string());
        captures.insert("1".to_string(), "users".to_string());
        captures.insert("2".to_string(), "123".to_string());

        TransformContext::new(request, "test".to_string())
            .with_captures(captures)
    }

    #[tokio::test]
    async fn test_simple_rewrite() {
        let config = UrlTransform {
            rewrite: "/api/v2/data".to_string(),
            preserve_query: false,
            add_query: None,
            remove_query: None,
        };
        let transformer = UrlTransformer::new(&config);

        let ctx = make_context("/api/v1/data", None);
        let result = transformer.transform(&ctx, None).await.unwrap();

        assert_eq!(result.new_url, Some("/api/v2/data".to_string()));
    }

    #[tokio::test]
    async fn test_rewrite_with_captures() {
        let config = UrlTransform {
            rewrite: "/api/v2/${resource}/${id}".to_string(),
            preserve_query: false,
            add_query: None,
            remove_query: None,
        };
        let transformer = UrlTransformer::new(&config);

        let ctx = make_context("/api/v1/users/123", None);
        let result = transformer.transform(&ctx, None).await.unwrap();

        assert_eq!(result.new_url, Some("/api/v2/users/123".to_string()));
    }

    #[tokio::test]
    async fn test_preserve_query() {
        let config = UrlTransform {
            rewrite: "/api/v2/data".to_string(),
            preserve_query: true,
            add_query: None,
            remove_query: None,
        };
        let transformer = UrlTransformer::new(&config);

        let ctx = make_context("/api/v1/data", Some("page=1&limit=10"));
        let result = transformer.transform(&ctx, None).await.unwrap();

        let url = result.new_url.unwrap();
        assert!(url.starts_with("/api/v2/data?"));
        assert!(url.contains("page=1"));
        assert!(url.contains("limit=10"));
    }

    #[tokio::test]
    async fn test_add_query() {
        let mut add_query = HashMap::new();
        add_query.insert("version".to_string(), "2".to_string());
        add_query.insert("resource".to_string(), "${resource}".to_string());

        let config = UrlTransform {
            rewrite: "/api/data".to_string(),
            preserve_query: false,
            add_query: Some(add_query),
            remove_query: None,
        };
        let transformer = UrlTransformer::new(&config);

        let ctx = make_context("/old/data", None);
        let result = transformer.transform(&ctx, None).await.unwrap();

        let url = result.new_url.unwrap();
        assert!(url.starts_with("/api/data?"));
        assert!(url.contains("version=2"));
        assert!(url.contains("resource=users"));
    }

    #[tokio::test]
    async fn test_remove_query() {
        let config = UrlTransform {
            rewrite: "/api/v2/data".to_string(),
            preserve_query: true,
            add_query: None,
            remove_query: Some(vec!["debug".to_string()]),
        };
        let transformer = UrlTransformer::new(&config);

        let ctx = make_context("/api/v1/data", Some("page=1&debug=true&limit=10"));
        let result = transformer.transform(&ctx, None).await.unwrap();

        let url = result.new_url.unwrap();
        assert!(url.contains("page=1"));
        assert!(url.contains("limit=10"));
        assert!(!url.contains("debug"));
    }
}
