//! Integration tests for the Transform Agent.

use sentinel_agent_transform::{TransformAgent, TransformConfig};
use sentinel_agent_transform::config::{PatternType, JsonTransform};

// =============================================================================
// Configuration Parsing Tests
// =============================================================================

#[test]
fn test_parse_minimal_config() {
    let yaml = r#"
version: "1"
rules: []
"#;
    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.version, "1");
    assert!(config.rules.is_empty());
}

#[test]
fn test_parse_full_config() {
    let yaml = r#"
version: "1"
settings:
  max_body_size: 5242880
  debug_headers: true
  timeout_ms: 200

rules:
  - name: "test-rule"
    description: "Test rule"
    enabled: true
    priority: 100
    match:
      path:
        pattern: "^/api/v1/(.*)$"
        type: regex
      methods: ["GET", "POST"]
    request:
      url:
        rewrite: "/api/v2/${1}"
        preserve_query: true
"#;
    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.settings.max_body_size, 5242880);
    assert!(config.settings.debug_headers);
    assert_eq!(config.settings.timeout_ms, 200);
    assert_eq!(config.rules.len(), 1);
    assert_eq!(config.rules[0].name, "test-rule");
    assert_eq!(config.rules[0].priority, 100);
}

#[test]
fn test_parse_json_config() {
    let json_str = r#"{
        "version": "1",
        "rules": [
            {
                "name": "json-rule",
                "enabled": true,
                "priority": 50,
                "match": {
                    "path": {
                        "pattern": "/test",
                        "type": "exact"
                    }
                }
            }
        ]
    }"#;
    let config: TransformConfig = serde_json::from_str(json_str).unwrap();
    assert_eq!(config.rules.len(), 1);
    assert_eq!(config.rules[0].name, "json-rule");
}

#[test]
fn test_disabled_rule() {
    let yaml = r#"
version: "1"
rules:
  - name: "disabled-rule"
    enabled: false
    priority: 100
    match:
      path:
        pattern: "/test"
        type: exact
"#;
    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(!config.rules[0].enabled);
}

// =============================================================================
// Path Matcher Tests
// =============================================================================

#[test]
fn test_exact_path_match_config() {
    let yaml = r#"
version: "1"
rules:
  - name: "exact-match"
    match:
      path:
        pattern: "/api/users"
        type: exact
"#;
    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
    let rule = &config.rules[0];
    let path_match = rule.matcher.path.as_ref().unwrap();
    assert_eq!(path_match.pattern, "/api/users");
    assert_eq!(path_match.pattern_type, PatternType::Exact);
}

#[test]
fn test_glob_path_match_config() {
    let yaml = r#"
version: "1"
rules:
  - name: "glob-match"
    match:
      path:
        pattern: "/api/*/items"
        type: glob
"#;
    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
    let rule = &config.rules[0];
    let path_match = rule.matcher.path.as_ref().unwrap();
    assert_eq!(path_match.pattern_type, PatternType::Glob);
}

#[test]
fn test_regex_path_match_config() {
    let yaml = r#"
version: "1"
rules:
  - name: "regex-match"
    match:
      path:
        pattern: "^/api/v(\\d+)/(?P<resource>.*)$"
        type: regex
"#;
    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
    let rule = &config.rules[0];
    let path_match = rule.matcher.path.as_ref().unwrap();
    assert_eq!(path_match.pattern_type, PatternType::Regex);
}

// =============================================================================
// Header Matcher Tests
// =============================================================================

#[test]
fn test_header_equals_config() {
    let yaml = r#"
version: "1"
rules:
  - name: "header-equals"
    match:
      headers:
        - name: "Content-Type"
          equals: "application/json"
"#;
    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
    let headers = config.rules[0].matcher.headers.as_ref().unwrap();
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name, "Content-Type");
    assert_eq!(headers[0].equals.as_ref().unwrap(), "application/json");
}

#[test]
fn test_header_contains_config() {
    let yaml = r#"
version: "1"
rules:
  - name: "header-contains"
    match:
      headers:
        - name: "Authorization"
          contains: "Bearer"
"#;
    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
    let headers = config.rules[0].matcher.headers.as_ref().unwrap();
    assert_eq!(headers[0].contains.as_ref().unwrap(), "Bearer");
}

#[test]
fn test_header_present_absent_config() {
    let yaml = r#"
version: "1"
rules:
  - name: "header-presence"
    match:
      headers:
        - name: "X-Api-Key"
          present: true
        - name: "X-Debug"
          absent: true
"#;
    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
    let headers = config.rules[0].matcher.headers.as_ref().unwrap();
    assert_eq!(headers.len(), 2);
    assert!(headers[0].present.unwrap_or(false));
    assert!(headers[1].absent.unwrap_or(false));
}

// =============================================================================
// Method Matcher Tests
// =============================================================================

#[test]
fn test_method_match_config() {
    let yaml = r#"
version: "1"
rules:
  - name: "method-match"
    match:
      methods: ["GET", "POST", "PUT"]
"#;
    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
    let methods = config.rules[0].matcher.methods.as_ref().unwrap();
    assert_eq!(methods.len(), 3);
    assert!(methods.contains(&"GET".to_string()));
    assert!(methods.contains(&"POST".to_string()));
    assert!(methods.contains(&"PUT".to_string()));
}

// =============================================================================
// Query Matcher Tests
// =============================================================================

#[test]
fn test_query_match_config() {
    let yaml = r#"
version: "1"
rules:
  - name: "query-match"
    match:
      query:
        - name: "api_key"
          present: true
        - name: "format"
          equals: "json"
"#;
    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
    let query = config.rules[0].matcher.query.as_ref().unwrap();
    assert_eq!(query.len(), 2);
    assert_eq!(query[0].name, "api_key");
    assert_eq!(query[1].equals.as_ref().unwrap(), "json");
}

// =============================================================================
// Body Matcher Tests
// =============================================================================

#[test]
fn test_body_match_config() {
    let yaml = r#"
version: "1"
rules:
  - name: "body-match"
    match:
      body:
        json:
          - path: "$.type"
            equals: "order"
          - path: "$.items"
            exists: true
"#;
    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
    let body = config.rules[0].matcher.body.as_ref().unwrap();
    let json = body.json.as_ref().unwrap();
    assert_eq!(json.len(), 2);
    assert_eq!(json[0].path, "$.type");
    assert!(json[1].exists.unwrap_or(false));
}

// =============================================================================
// URL Transformer Tests
// =============================================================================

#[test]
fn test_url_rewrite_config() {
    let yaml = r#"
version: "1"
rules:
  - name: "url-rewrite"
    match:
      path:
        pattern: "^/api/v1/(.*)$"
        type: regex
    request:
      url:
        rewrite: "/api/v2/${1}"
        preserve_query: true
"#;
    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
    let url = config.rules[0].request.as_ref().unwrap().url.as_ref().unwrap();
    assert_eq!(url.rewrite, "/api/v2/${1}");
    assert!(url.preserve_query);
}

#[test]
fn test_url_query_manipulation_config() {
    let yaml = r#"
version: "1"
rules:
  - name: "url-query"
    match:
      path:
        pattern: "/api"
        type: exact
    request:
      url:
        rewrite: "/api/v2"
        add_query:
          version: "2"
          trace_id: "${correlation_id}"
        remove_query:
          - "debug"
          - "internal"
"#;
    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
    let url = config.rules[0].request.as_ref().unwrap().url.as_ref().unwrap();
    let add_query = url.add_query.as_ref().unwrap();
    assert_eq!(add_query.get("version").unwrap(), "2");
    let remove_query = url.remove_query.as_ref().unwrap();
    assert!(remove_query.contains(&"debug".to_string()));
}

// =============================================================================
// Header Transformer Tests
// =============================================================================

#[test]
fn test_header_transform_config() {
    let yaml = r#"
version: "1"
rules:
  - name: "header-transform"
    match:
      path:
        pattern: "/api"
        type: exact
    request:
      headers:
        add:
          - name: "X-Forwarded-By"
            value: "sentinel"
        set:
          - name: "User-Agent"
            value: "transform-agent/1.0"
        remove:
          - "X-Debug-Mode"
"#;
    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
    let headers = config.rules[0].request.as_ref().unwrap().headers.as_ref().unwrap();
    assert_eq!(headers.add.as_ref().unwrap().len(), 1);
    assert_eq!(headers.add.as_ref().unwrap()[0].name, "X-Forwarded-By");
    assert_eq!(headers.set.as_ref().unwrap().len(), 1);
    assert_eq!(headers.remove.as_ref().unwrap().len(), 1);
}

#[test]
fn test_response_header_transform_config() {
    let yaml = r#"
version: "1"
rules:
  - name: "response-headers"
    match:
      path:
        pattern: "/api"
        type: exact
    response:
      headers:
        add:
          - name: "X-Served-By"
            value: "sentinel"
        remove:
          - "Server"
          - "X-Powered-By"
"#;
    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
    let headers = config.rules[0].response.as_ref().unwrap().headers.as_ref().unwrap();
    assert_eq!(headers.add.as_ref().unwrap().len(), 1);
    assert_eq!(headers.remove.as_ref().unwrap().len(), 2);
}

// =============================================================================
// JSON Transformer Tests (using JSON format for enum parsing)
// =============================================================================

#[test]
fn test_json_set_operation() {
    // Test JSON operations using JSON format (more reliable for enum parsing)
    let json_str = r#"{
        "operations": [
            {"set": {"path": "$.api_version", "value": "v2"}}
        ]
    }"#;
    let transform: JsonTransform = serde_json::from_str(json_str).unwrap();
    assert_eq!(transform.operations.len(), 1);
}

#[test]
fn test_json_delete_operation() {
    let json_str = r#"{
        "operations": [
            {"delete": ["$.debug", "$.internal_flags"]}
        ]
    }"#;
    let transform: JsonTransform = serde_json::from_str(json_str).unwrap();
    assert_eq!(transform.operations.len(), 1);
}

#[test]
fn test_json_rename_operation() {
    let json_str = r#"{
        "operations": [
            {"rename": {"from": "$.userId", "to": "$.user_id"}}
        ]
    }"#;
    let transform: JsonTransform = serde_json::from_str(json_str).unwrap();
    assert_eq!(transform.operations.len(), 1);
}

#[test]
fn test_json_wrap_operation() {
    let json_str = r#"{
        "operations": [
            {"wrap": {"path": "$", "key": "data"}}
        ]
    }"#;
    let transform: JsonTransform = serde_json::from_str(json_str).unwrap();
    assert_eq!(transform.operations.len(), 1);
}

#[test]
fn test_json_merge_operation() {
    let json_str = r#"{
        "operations": [
            {"merge": {"path": "$.metadata", "with": {"processed": true, "source": "sentinel"}}}
        ]
    }"#;
    let transform: JsonTransform = serde_json::from_str(json_str).unwrap();
    assert_eq!(transform.operations.len(), 1);
}

#[test]
fn test_json_copy_move_operations() {
    let json_str = r#"{
        "operations": [
            {"copy": {"from": "$.user.id", "to": "$.audit.user_id"}},
            {"move": {"from": "$.temp", "to": "$.permanent"}}
        ]
    }"#;
    let transform: JsonTransform = serde_json::from_str(json_str).unwrap();
    assert_eq!(transform.operations.len(), 2);
}

#[test]
fn test_json_multiple_operations() {
    let json_str = r#"{
        "operations": [
            {"set": {"path": "$.version", "value": "2"}},
            {"delete": ["$.debug"]},
            {"rename": {"from": "$.old_field", "to": "$.new_field"}},
            {"wrap": {"path": "$", "key": "payload"}}
        ]
    }"#;
    let transform: JsonTransform = serde_json::from_str(json_str).unwrap();
    assert_eq!(transform.operations.len(), 4);
}

// =============================================================================
// Response Matching Tests
// =============================================================================

#[test]
fn test_response_match_config() {
    let yaml = r#"
version: "1"
rules:
  - name: "response-match"
    match:
      path:
        pattern: "/api"
        type: exact
      response:
        status_codes: [200, 201]
        content_types:
          - "application/json"
"#;
    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
    let response = config.rules[0].matcher.response.as_ref().unwrap();
    let status_codes = response.status_codes.as_ref().unwrap();
    assert_eq!(status_codes.len(), 2);
    assert!(status_codes.contains(&200));
    let content_types = response.content_types.as_ref().unwrap();
    assert!(content_types.contains(&"application/json".to_string()));
}

// =============================================================================
// Rule Priority Tests
// =============================================================================

#[test]
fn test_rule_priority_ordering() {
    let yaml = r#"
version: "1"
rules:
  - name: "low-priority"
    priority: 10
    match:
      path:
        pattern: "/api"
        type: exact
  - name: "high-priority"
    priority: 100
    match:
      path:
        pattern: "/api"
        type: exact
  - name: "medium-priority"
    priority: 50
    match:
      path:
        pattern: "/api"
        type: exact
"#;
    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.rules[0].priority, 10);
    assert_eq!(config.rules[1].priority, 100);
    assert_eq!(config.rules[2].priority, 50);
}

// =============================================================================
// Agent Creation Tests
// =============================================================================

#[tokio::test]
async fn test_agent_creation_default() {
    let config = TransformConfig::default();
    let agent = TransformAgent::new(config);
    assert!(agent.is_ok());
}

#[tokio::test]
async fn test_agent_creation_with_rules() {
    let yaml = r#"
version: "1"
rules:
  - name: "test-rule"
    priority: 100
    match:
      path:
        pattern: "^/api/v1/(.*)$"
        type: regex
    request:
      url:
        rewrite: "/api/v2/${1}"
"#;
    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
    let agent = TransformAgent::new(config);
    assert!(agent.is_ok());
}

#[tokio::test]
async fn test_agent_creation_complex_config() {
    let yaml = r#"
version: "1"
settings:
  max_body_size: 1048576
  debug_headers: true
  timeout_ms: 50

rules:
  - name: "api-migration"
    priority: 100
    match:
      path:
        pattern: "^/api/v1/(?P<resource>.*)$"
        type: regex
      methods: ["GET", "POST"]
      headers:
        - name: "Content-Type"
          equals: "application/json"
    request:
      url:
        rewrite: "/api/v2/${resource}"
        preserve_query: true
        add_query:
          migrated: "true"
      headers:
        add:
          - name: "X-API-Version"
            value: "2"
        remove:
          - "X-Legacy"
    response:
      headers:
        add:
          - name: "X-Transformed"
            value: "true"

  - name: "response-sanitize"
    priority: 50
    match:
      path:
        pattern: "/api/.*"
        type: regex
      response:
        content_types:
          - "application/json"
    response:
      headers:
        remove:
          - "Server"
          - "X-Powered-By"
"#;
    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
    let agent = TransformAgent::new(config);
    assert!(agent.is_ok());
}

// =============================================================================
// Variable Interpolation Tests
// =============================================================================

#[test]
fn test_variable_interpolation_in_config() {
    let yaml = r#"
version: "1"
rules:
  - name: "interpolation-test"
    match:
      path:
        pattern: "/api"
        type: exact
    request:
      headers:
        add:
          - name: "X-Request-Id"
            value: "${correlation_id}"
          - name: "X-Method"
            value: "${request.method}"
      url:
        rewrite: "/v2${request.path}"
        add_query:
          client: "${request.client_ip}"
"#;
    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
    let headers = config.rules[0].request.as_ref().unwrap().headers.as_ref().unwrap();
    let add = headers.add.as_ref().unwrap();
    assert_eq!(add[0].value, "${correlation_id}");
    assert_eq!(add[1].value, "${request.method}");
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[test]
fn test_empty_rules() {
    let yaml = r#"
version: "1"
rules: []
"#;
    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(config.rules.is_empty());
}

#[test]
fn test_rule_with_only_match() {
    let yaml = r#"
version: "1"
rules:
  - name: "match-only"
    match:
      path:
        pattern: "/test"
        type: exact
"#;
    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(config.rules[0].request.is_none());
    assert!(config.rules[0].response.is_none());
}

#[test]
fn test_rule_with_only_response() {
    let yaml = r#"
version: "1"
rules:
  - name: "response-only"
    match:
      path:
        pattern: "/test"
        type: exact
    response:
      headers:
        add:
          - name: "X-Test"
            value: "test"
"#;
    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(config.rules[0].request.is_none());
    assert!(config.rules[0].response.is_some());
}

#[test]
fn test_default_settings() {
    let yaml = r#"
version: "1"
rules: []
"#;
    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
    // Check default settings are applied
    assert_eq!(config.settings.max_body_size, 10 * 1024 * 1024);
    assert!(!config.settings.debug_headers);
}

// =============================================================================
// Comprehensive E2E Config Test
// =============================================================================

#[tokio::test]
async fn test_full_e2e_config() {
    let yaml = r#"
version: "1"

settings:
  max_body_size: 10485760
  template_dir: "/etc/sentinel/templates"
  cache_templates: true
  debug_headers: true
  timeout_ms: 100

rules:
  # High priority: API version migration
  - name: "api-v1-to-v2"
    description: "Migrate v1 API calls to v2 endpoint"
    enabled: true
    priority: 100
    match:
      path:
        pattern: "^/api/v1/(.*)$"
        type: regex
      methods: ["GET", "POST", "PUT", "DELETE"]
      headers:
        - name: "Content-Type"
          contains: "json"
    request:
      url:
        rewrite: "/api/v2/${1}"
        preserve_query: true
        add_query:
          api_version: "2"
      headers:
        add:
          - name: "X-Migrated-From"
            value: "v1"
        set:
          - name: "X-API-Version"
            value: "2"
    response:
      headers:
        add:
          - name: "X-Transform-Applied"
            value: "api-v1-to-v2"

  # Medium priority: Add tracking headers
  - name: "add-tracking"
    enabled: true
    priority: 50
    match:
      path:
        pattern: "/api/.*"
        type: regex
    request:
      headers:
        add:
          - name: "X-Correlation-Id"
            value: "${correlation_id}"
          - name: "X-Request-Time"
            value: "${now}"

  # Low priority: Response sanitization
  - name: "sanitize-response"
    enabled: true
    priority: 10
    match:
      path:
        pattern: "/api/.*"
        type: regex
      response:
        status_codes: [200, 201, 202]
        content_types:
          - "application/json"
    response:
      headers:
        remove:
          - "Server"
          - "X-Powered-By"
          - "X-AspNet-Version"
"#;

    let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();

    // Verify settings
    assert_eq!(config.settings.max_body_size, 10485760);
    assert!(config.settings.debug_headers);
    assert_eq!(config.settings.timeout_ms, 100);

    // Verify rules count and order
    assert_eq!(config.rules.len(), 3);
    assert_eq!(config.rules[0].name, "api-v1-to-v2");
    assert_eq!(config.rules[0].priority, 100);
    assert_eq!(config.rules[1].name, "add-tracking");
    assert_eq!(config.rules[1].priority, 50);
    assert_eq!(config.rules[2].name, "sanitize-response");
    assert_eq!(config.rules[2].priority, 10);

    // Verify agent can be created
    let agent = TransformAgent::new(config);
    assert!(agent.is_ok());
}
