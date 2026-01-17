//! Transform context for variable resolution and interpolation.

use regex::Regex;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::sync::LazyLock;

/// Regex for matching variable expressions like ${...}
static VAR_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{([^}]+)\}").unwrap()
});

/// Context available during transformations.
#[derive(Debug, Clone)]
pub struct TransformContext {
    /// Original request information
    pub request: RequestInfo,
    /// Response information (if in response phase)
    pub response: Option<ResponseInfo>,
    /// Captured groups from regex matching
    pub captures: HashMap<String, String>,
    /// Parsed request body (if JSON)
    pub body_json: Option<JsonValue>,
    /// Parsed response body (if JSON)
    pub response_body_json: Option<JsonValue>,
    /// Current timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Correlation ID
    pub correlation_id: String,
}

/// Request information for context.
#[derive(Debug, Clone)]
pub struct RequestInfo {
    /// HTTP method
    pub method: String,
    /// Request path (without query string)
    pub path: String,
    /// Query string (without leading ?)
    pub query_string: Option<String>,
    /// Parsed query parameters
    pub query_params: HashMap<String, Vec<String>>,
    /// Request headers
    pub headers: HashMap<String, Vec<String>>,
    /// Client IP address
    pub client_ip: String,
}

/// Response information for context.
#[derive(Debug, Clone)]
pub struct ResponseInfo {
    /// HTTP status code
    pub status: u16,
    /// Status text
    pub status_text: String,
    /// Response headers
    pub headers: HashMap<String, Vec<String>>,
}

impl TransformContext {
    /// Create a new transform context.
    pub fn new(request: RequestInfo, correlation_id: String) -> Self {
        Self {
            request,
            response: None,
            captures: HashMap::new(),
            body_json: None,
            response_body_json: None,
            timestamp: chrono::Utc::now(),
            correlation_id,
        }
    }

    /// Add response information to the context.
    pub fn with_response(mut self, response: ResponseInfo) -> Self {
        self.response = Some(response);
        self
    }

    /// Add regex captures to the context.
    pub fn with_captures(mut self, captures: HashMap<String, String>) -> Self {
        self.captures = captures;
        self
    }

    /// Add parsed request body JSON.
    pub fn with_body_json(mut self, body: JsonValue) -> Self {
        self.body_json = Some(body);
        self
    }

    /// Add parsed response body JSON.
    pub fn with_response_body_json(mut self, body: JsonValue) -> Self {
        self.response_body_json = Some(body);
        self
    }

    /// Resolve a variable expression.
    ///
    /// Supports:
    /// - `${request.path}` - Request path
    /// - `${request.method}` - HTTP method
    /// - `${request.query}` - Query string
    /// - `${request.header.X-Custom}` - Request header value
    /// - `${response.status}` - Response status code
    /// - `${response.header.Content-Type}` - Response header value
    /// - `${captures.name}` or `${name}` - Regex capture group
    /// - `${body.field.subfield}` - Request body JSON path
    /// - `${response_body.field}` - Response body JSON path
    /// - `${correlation_id}` - Correlation ID
    /// - `${now}` - Current timestamp (ISO 8601)
    /// - `${0}`, `${1}`, etc. - Numbered capture groups
    pub fn resolve(&self, expr: &str) -> Option<String> {
        let parts: Vec<&str> = expr.splitn(2, '.').collect();

        match parts[0] {
            "request" => self.resolve_request(parts.get(1).unwrap_or(&"")),
            "response" => self.resolve_response(parts.get(1).unwrap_or(&"")),
            "captures" => {
                let key = parts.get(1)?;
                self.captures.get(*key).cloned()
            }
            "body" => {
                let path = parts.get(1).unwrap_or(&"");
                self.resolve_json_path(&self.body_json, path)
            }
            "response_body" => {
                let path = parts.get(1).unwrap_or(&"");
                self.resolve_json_path(&self.response_body_json, path)
            }
            "correlation_id" => Some(self.correlation_id.clone()),
            "now" => Some(self.timestamp.to_rfc3339()),
            // Check for numbered captures or named captures without prefix
            other => {
                // Try as numbered capture first
                if other.parse::<usize>().is_ok() {
                    self.captures.get(other).cloned()
                } else {
                    // Try as named capture
                    self.captures.get(other).cloned()
                }
            }
        }
    }

    /// Interpolate all ${...} variables in a string.
    pub fn interpolate(&self, template: &str) -> String {
        VAR_REGEX.replace_all(template, |caps: &regex::Captures| {
            let var_name = &caps[1];
            self.resolve(var_name).unwrap_or_default()
        }).to_string()
    }

    fn resolve_request(&self, path: &str) -> Option<String> {
        let parts: Vec<&str> = path.splitn(2, '.').collect();

        match parts[0] {
            "method" => Some(self.request.method.clone()),
            "path" => Some(self.request.path.clone()),
            "query" => self.request.query_string.clone(),
            "client_ip" => Some(self.request.client_ip.clone()),
            "header" => {
                let name = parts.get(1)?.to_lowercase();
                self.request.headers.get(&name)?.first().cloned()
            }
            "query_param" => {
                let name = parts.get(1)?;
                self.request.query_params.get(*name)?.first().cloned()
            }
            _ => None,
        }
    }

    fn resolve_response(&self, path: &str) -> Option<String> {
        let resp = self.response.as_ref()?;
        let parts: Vec<&str> = path.splitn(2, '.').collect();

        match parts[0] {
            "status" => Some(resp.status.to_string()),
            "status_text" => Some(resp.status_text.clone()),
            "header" => {
                let name = parts.get(1)?.to_lowercase();
                resp.headers.get(&name)?.first().cloned()
            }
            _ => None,
        }
    }

    fn resolve_json_path(&self, json: &Option<JsonValue>, path: &str) -> Option<String> {
        let json = json.as_ref()?;
        let mut current = json;

        for part in path.split('.') {
            if part.is_empty() {
                continue;
            }

            // Handle array indexing like "items.0" or "items[0]"
            let (key, index) = if let Some(bracket_pos) = part.find('[') {
                let key = &part[..bracket_pos];
                let idx_str = part[bracket_pos + 1..].trim_end_matches(']');
                let idx: usize = idx_str.parse().ok()?;
                (key, Some(idx))
            } else if let Ok(idx) = part.parse::<usize>() {
                ("", Some(idx))
            } else {
                (part, None)
            };

            // Navigate to key if present
            if !key.is_empty() {
                current = current.get(key)?;
            }

            // Navigate to index if present
            if let Some(idx) = index {
                current = current.get(idx)?;
            }
        }

        match current {
            JsonValue::String(s) => Some(s.clone()),
            JsonValue::Number(n) => Some(n.to_string()),
            JsonValue::Bool(b) => Some(b.to_string()),
            JsonValue::Null => Some("null".to_string()),
            _ => Some(current.to_string()),
        }
    }
}

impl RequestInfo {
    /// Get a single header value.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_lowercase())
            .and_then(|v| v.first())
            .map(|s| s.as_str())
    }
}

impl ResponseInfo {
    /// Get a single header value.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_lowercase())
            .and_then(|v| v.first())
            .map(|s| s.as_str())
    }
}

/// Get status text for a status code.
pub fn status_text(code: u16) -> String {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    }.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_context() -> TransformContext {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), vec!["application/json".to_string()]);
        headers.insert("x-custom".to_string(), vec!["custom-value".to_string()]);

        let mut query_params = HashMap::new();
        query_params.insert("page".to_string(), vec!["1".to_string()]);

        let request = RequestInfo {
            method: "GET".to_string(),
            path: "/api/users/123".to_string(),
            query_string: Some("page=1".to_string()),
            query_params,
            headers,
            client_ip: "192.168.1.1".to_string(),
        };

        let mut captures = HashMap::new();
        captures.insert("0".to_string(), "/api/users/123".to_string());
        captures.insert("1".to_string(), "users".to_string());
        captures.insert("2".to_string(), "123".to_string());
        captures.insert("resource".to_string(), "users".to_string());
        captures.insert("id".to_string(), "123".to_string());

        let body_json = serde_json::json!({
            "user": {
                "name": "John",
                "age": 30
            },
            "items": ["a", "b", "c"]
        });

        TransformContext::new(request, "test-correlation-id".to_string())
            .with_captures(captures)
            .with_body_json(body_json)
    }

    #[test]
    fn test_resolve_request() {
        let ctx = make_context();

        assert_eq!(ctx.resolve("request.method"), Some("GET".to_string()));
        assert_eq!(ctx.resolve("request.path"), Some("/api/users/123".to_string()));
        assert_eq!(ctx.resolve("request.query"), Some("page=1".to_string()));
        assert_eq!(ctx.resolve("request.client_ip"), Some("192.168.1.1".to_string()));
        assert_eq!(ctx.resolve("request.header.x-custom"), Some("custom-value".to_string()));
    }

    #[test]
    fn test_resolve_captures() {
        let ctx = make_context();

        assert_eq!(ctx.resolve("captures.resource"), Some("users".to_string()));
        assert_eq!(ctx.resolve("captures.id"), Some("123".to_string()));
        assert_eq!(ctx.resolve("1"), Some("users".to_string()));
        assert_eq!(ctx.resolve("2"), Some("123".to_string()));
        assert_eq!(ctx.resolve("resource"), Some("users".to_string()));
    }

    #[test]
    fn test_resolve_body() {
        let ctx = make_context();

        assert_eq!(ctx.resolve("body.user.name"), Some("John".to_string()));
        assert_eq!(ctx.resolve("body.user.age"), Some("30".to_string()));
        // Array elements that are strings return the unquoted string value
        assert_eq!(ctx.resolve("body.items.0"), Some("a".to_string()));
    }

    #[test]
    fn test_interpolate() {
        let ctx = make_context();

        let result = ctx.interpolate("/api/v2/${resource}/${id}");
        assert_eq!(result, "/api/v2/users/123");

        let result = ctx.interpolate("User: ${body.user.name}");
        assert_eq!(result, "User: John");

        let result = ctx.interpolate("Method: ${request.method}, Path: ${request.path}");
        assert_eq!(result, "Method: GET, Path: /api/users/123");
    }

    #[test]
    fn test_correlation_id() {
        let ctx = make_context();
        assert_eq!(ctx.resolve("correlation_id"), Some("test-correlation-id".to_string()));
    }
}
