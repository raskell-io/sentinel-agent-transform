//! Configuration types for the Transform agent.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Main configuration for the Transform agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TransformConfig {
    /// Configuration version
    pub version: String,
    /// Global settings
    pub settings: Settings,
    /// Transform rules (evaluated in priority order)
    pub rules: Vec<Rule>,
}

impl Default for TransformConfig {
    fn default() -> Self {
        Self {
            version: "1".to_string(),
            settings: Settings::default(),
            rules: vec![],
        }
    }
}

/// Global settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Maximum body size to buffer for transformation (bytes)
    pub max_body_size: usize,
    /// Template directory path
    pub template_dir: String,
    /// Enable template caching
    pub cache_templates: bool,
    /// Enable debug headers (X-Transform-Rule, X-Transform-Time)
    pub debug_headers: bool,
    /// Default timeout for transformations (ms)
    pub timeout_ms: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            max_body_size: 10 * 1024 * 1024, // 10MB
            template_dir: "/etc/sentinel/templates".to_string(),
            cache_templates: true,
            debug_headers: false,
            timeout_ms: 100,
        }
    }
}

/// A transform rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Rule name (for logging/debugging)
    pub name: String,
    /// Optional description
    #[serde(default)]
    pub description: String,
    /// Whether the rule is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Priority (higher = evaluated first)
    #[serde(default = "default_priority")]
    pub priority: i32,
    /// Matching conditions
    #[serde(rename = "match")]
    pub matcher: RuleMatcher,
    /// Request transforms
    #[serde(default)]
    pub request: Option<RequestTransform>,
    /// Response transforms
    #[serde(default)]
    pub response: Option<ResponseTransform>,
}

fn default_true() -> bool {
    true
}

fn default_priority() -> i32 {
    50
}

/// Matching conditions for a rule.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleMatcher {
    /// Path matching
    #[serde(default)]
    pub path: Option<PathMatcher>,
    /// HTTP methods to match
    #[serde(default)]
    pub methods: Option<Vec<String>>,
    /// Header conditions
    #[serde(default)]
    pub headers: Option<Vec<HeaderMatcher>>,
    /// Query parameter matching
    #[serde(default)]
    pub query: Option<Vec<QueryMatcher>>,
    /// Request body matching (JSON)
    #[serde(default)]
    pub body: Option<BodyMatcher>,
    /// Response matching (for response-phase transforms)
    #[serde(default)]
    pub response: Option<ResponseMatcher>,
}

/// Path matcher configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathMatcher {
    /// The pattern to match
    pub pattern: String,
    /// Match type: exact, glob, regex
    #[serde(default = "default_pattern_type", rename = "type")]
    pub pattern_type: PatternType,
}

/// Pattern matching type.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PatternType {
    /// Exact string match
    Exact,
    /// Glob pattern (*, ?)
    Glob,
    /// Regular expression
    #[default]
    Regex,
}

fn default_pattern_type() -> PatternType {
    PatternType::Regex
}

/// Header matcher configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderMatcher {
    /// Header name (case-insensitive)
    pub name: String,
    /// Exact value match
    #[serde(default)]
    pub equals: Option<String>,
    /// Contains substring
    #[serde(default)]
    pub contains: Option<String>,
    /// Regex match
    #[serde(default)]
    pub matches: Option<String>,
    /// Header must be present
    #[serde(default)]
    pub present: Option<bool>,
    /// Header must be absent
    #[serde(default)]
    pub absent: Option<bool>,
}

/// Query parameter matcher configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryMatcher {
    /// Parameter name
    pub name: String,
    /// Exact value match
    #[serde(default)]
    pub equals: Option<String>,
    /// Contains substring
    #[serde(default)]
    pub contains: Option<String>,
    /// Parameter must be present
    #[serde(default)]
    pub present: Option<bool>,
}

/// Request body matcher configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BodyMatcher {
    /// JSON path conditions
    #[serde(default)]
    pub json: Option<Vec<JsonCondition>>,
}

/// JSON path condition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonCondition {
    /// JSON path expression
    pub path: String,
    /// Expected value (exact match)
    #[serde(default)]
    pub equals: Option<serde_json::Value>,
    /// Contains substring (for string values)
    #[serde(default)]
    pub contains: Option<String>,
    /// Value must exist
    #[serde(default)]
    pub exists: Option<bool>,
}

/// Response matcher configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMatcher {
    /// Status codes to match
    #[serde(default)]
    pub status_codes: Option<Vec<u16>>,
    /// Content-Types to match
    #[serde(default)]
    pub content_types: Option<Vec<String>>,
}

/// Request transformations.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RequestTransform {
    /// URL rewriting
    #[serde(default)]
    pub url: Option<UrlTransform>,
    /// HTTP method override
    #[serde(default)]
    pub method: Option<String>,
    /// Header modifications
    #[serde(default)]
    pub headers: Option<HeaderTransform>,
    /// Body transformations
    #[serde(default)]
    pub body: Option<BodyTransform>,
}

/// Response transformations.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResponseTransform {
    /// Header modifications
    #[serde(default)]
    pub headers: Option<HeaderTransform>,
    /// Body transformations
    #[serde(default)]
    pub body: Option<BodyTransform>,
    /// Template-based response
    #[serde(default)]
    pub template: Option<TemplateConfig>,
    /// Status code override
    #[serde(default)]
    pub status: Option<u16>,
}

/// URL transformation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlTransform {
    /// New URL pattern (supports variable substitution)
    pub rewrite: String,
    /// Preserve query string from original request
    #[serde(default = "default_true")]
    pub preserve_query: bool,
    /// Additional query parameters to add
    #[serde(default)]
    pub add_query: Option<HashMap<String, String>>,
    /// Query parameters to remove
    #[serde(default)]
    pub remove_query: Option<Vec<String>>,
}

/// Header transformation configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeaderTransform {
    /// Headers to add (if not present)
    #[serde(default)]
    pub add: Option<Vec<HeaderValue>>,
    /// Headers to set (overwrite)
    #[serde(default)]
    pub set: Option<Vec<HeaderValue>>,
    /// Headers to remove
    #[serde(default)]
    pub remove: Option<Vec<String>>,
}

/// Header name-value pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderValue {
    /// Header name
    pub name: String,
    /// Header value (supports variable substitution)
    pub value: String,
}

/// Body transformation configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BodyTransform {
    /// JSON transformations
    #[serde(default)]
    pub json: Option<JsonTransform>,
    /// Content-Type conversion
    #[serde(default)]
    pub convert: Option<ConvertConfig>,
    /// Clear/empty the body
    #[serde(default)]
    pub clear: Option<bool>,
    /// Replace with static content
    #[serde(default)]
    pub replace: Option<String>,
}

/// JSON body transformation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonTransform {
    /// List of operations to apply in order
    pub operations: Vec<JsonOperation>,
}

/// JSON transformation operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JsonOperation {
    /// Set a value at a JSON path
    Set {
        path: String,
        value: serde_json::Value,
    },
    /// Delete values at JSON paths
    Delete(Vec<String>),
    /// Rename a field
    Rename {
        from: String,
        to: String,
    },
    /// Wrap a value in an object with a key
    Wrap {
        path: String,
        key: String,
    },
    /// Merge additional fields into an object
    Merge {
        path: String,
        with: serde_json::Value,
    },
    /// Copy a value from one path to another
    Copy {
        from: String,
        to: String,
    },
    /// Move a value from one path to another
    Move {
        from: String,
        to: String,
    },
}

/// Content-Type conversion configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvertConfig {
    /// Source format
    pub from: ContentFormat,
    /// Target format
    pub to: ContentFormat,
    /// Conversion options
    #[serde(default)]
    pub options: ConvertOptions,
}

/// Content format for conversion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContentFormat {
    Json,
    Xml,
    FormUrlencoded,
}

/// Conversion options.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConvertOptions {
    /// Keys to force as arrays in XML->JSON conversion
    #[serde(default)]
    pub array_keys: Vec<String>,
    /// Root element name for JSON->XML conversion
    #[serde(default)]
    pub root_element: Option<String>,
    /// Pretty print output
    #[serde(default)]
    pub pretty: bool,
}

/// Template configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateConfig {
    /// Template file name (relative to template_dir)
    pub name: String,
    /// Additional context variables
    #[serde(default)]
    pub context: HashMap<String, String>,
    /// Content-Type for the response
    #[serde(default)]
    pub content_type: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TransformConfig::default();
        assert_eq!(config.version, "1");
        assert!(config.rules.is_empty());
        assert_eq!(config.settings.max_body_size, 10 * 1024 * 1024);
    }

    #[test]
    fn test_config_parsing() {
        let yaml = r#"
version: "1"
settings:
  debug_headers: true
rules:
  - name: "test-rule"
    match:
      path:
        pattern: "^/api/.*$"
        type: regex
    request:
      url:
        rewrite: "/v2${0}"
"#;
        let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].name, "test-rule");
        assert!(config.settings.debug_headers);
    }

    #[test]
    fn test_json_operation_parsing() {
        // Test individual operations using JSON format which is more predictable
        let json = r#"{
            "operations": [
                {"set": {"path": "$.name", "value": "test"}},
                {"delete": ["$.internal", "$.debug"]},
                {"rename": {"from": "$.old_name", "to": "$.new_name"}},
                {"wrap": {"path": "$", "key": "data"}}
            ]
        }"#;
        let transform: JsonTransform = serde_json::from_str(json).unwrap();
        assert_eq!(transform.operations.len(), 4);
    }
}
