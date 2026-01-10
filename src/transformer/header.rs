//! Header manipulation transformer.

use super::{TransformError, TransformResult, Transformer};
use crate::config::HeaderTransform;
use crate::context::TransformContext;
use async_trait::async_trait;

/// Header manipulation transformer.
pub struct HeaderTransformer {
    /// Headers to add (if not present)
    add: Vec<(String, String)>,
    /// Headers to set (overwrite)
    set: Vec<(String, String)>,
    /// Headers to remove
    remove: Vec<String>,
}

impl HeaderTransformer {
    /// Create a new header transformer from configuration.
    pub fn new(config: &HeaderTransform) -> Self {
        let add = config.add.as_ref()
            .map(|headers| {
                headers.iter()
                    .map(|h| (h.name.clone(), h.value.clone()))
                    .collect()
            })
            .unwrap_or_default();

        let set = config.set.as_ref()
            .map(|headers| {
                headers.iter()
                    .map(|h| (h.name.clone(), h.value.clone()))
                    .collect()
            })
            .unwrap_or_default();

        let remove = config.remove.clone().unwrap_or_default();

        Self { add, set, remove }
    }
}

#[async_trait]
impl Transformer for HeaderTransformer {
    async fn transform(
        &self,
        ctx: &TransformContext,
        _body: Option<&[u8]>,
    ) -> Result<TransformResult, TransformError> {
        let mut result = TransformResult::none();

        // Add headers to remove
        for name in &self.remove {
            result = result.remove_header(name.clone());
        }

        // Add "set" headers (these will overwrite)
        for (name, value) in &self.set {
            let interpolated = ctx.interpolate(value);
            result = result.add_header(name.clone(), interpolated);
        }

        // Add "add" headers
        // Note: The actual "only if not present" logic would need to be
        // handled by the proxy, but we can still track intent
        for (name, value) in &self.add {
            let interpolated = ctx.interpolate(value);
            result = result.add_header(name.clone(), interpolated);
        }

        Ok(result)
    }

    fn name(&self) -> &'static str {
        "header_transformer"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HeaderValue;
    use crate::context::RequestInfo;
    use std::collections::HashMap;

    fn make_context() -> TransformContext {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), vec!["application/json".to_string()]);

        let request = RequestInfo {
            method: "GET".to_string(),
            path: "/test".to_string(),
            query_string: None,
            query_params: HashMap::new(),
            headers,
            client_ip: "192.168.1.1".to_string(),
        };

        let mut captures = HashMap::new();
        captures.insert("version".to_string(), "2".to_string());

        TransformContext::new(request, "test-123".to_string())
            .with_captures(captures)
    }

    #[tokio::test]
    async fn test_add_headers() {
        let config = HeaderTransform {
            add: Some(vec![
                HeaderValue {
                    name: "X-Custom".to_string(),
                    value: "value".to_string(),
                },
            ]),
            set: None,
            remove: None,
        };
        let transformer = HeaderTransformer::new(&config);

        let ctx = make_context();
        let result = transformer.transform(&ctx, None).await.unwrap();

        assert_eq!(result.add_headers.len(), 1);
        assert_eq!(result.add_headers[0], ("X-Custom".to_string(), "value".to_string()));
    }

    #[tokio::test]
    async fn test_remove_headers() {
        let config = HeaderTransform {
            add: None,
            set: None,
            remove: Some(vec!["X-Debug".to_string(), "X-Internal".to_string()]),
        };
        let transformer = HeaderTransformer::new(&config);

        let ctx = make_context();
        let result = transformer.transform(&ctx, None).await.unwrap();

        assert_eq!(result.remove_headers.len(), 2);
        assert!(result.remove_headers.contains(&"X-Debug".to_string()));
        assert!(result.remove_headers.contains(&"X-Internal".to_string()));
    }

    #[tokio::test]
    async fn test_interpolation() {
        let config = HeaderTransform {
            add: Some(vec![
                HeaderValue {
                    name: "X-Version".to_string(),
                    value: "${version}".to_string(),
                },
                HeaderValue {
                    name: "X-Client-IP".to_string(),
                    value: "${request.client_ip}".to_string(),
                },
                HeaderValue {
                    name: "X-Request-ID".to_string(),
                    value: "${correlation_id}".to_string(),
                },
            ]),
            set: None,
            remove: None,
        };
        let transformer = HeaderTransformer::new(&config);

        let ctx = make_context();
        let result = transformer.transform(&ctx, None).await.unwrap();

        assert_eq!(result.add_headers.len(), 3);

        let headers: HashMap<_, _> = result.add_headers.into_iter().collect();
        assert_eq!(headers.get("X-Version"), Some(&"2".to_string()));
        assert_eq!(headers.get("X-Client-IP"), Some(&"192.168.1.1".to_string()));
        assert_eq!(headers.get("X-Request-ID"), Some(&"test-123".to_string()));
    }
}
