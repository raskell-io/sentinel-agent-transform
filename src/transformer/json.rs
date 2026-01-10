//! JSON body transformer.

use super::{TransformError, TransformResult, Transformer};
use crate::config::{JsonOperation, JsonTransform};
use crate::context::TransformContext;
use async_trait::async_trait;
use serde_json::Value as JsonValue;

/// JSON body transformer.
pub struct JsonTransformer {
    /// Operations to apply in order
    operations: Vec<JsonOperation>,
}

impl JsonTransformer {
    /// Create a new JSON transformer from configuration.
    pub fn new(config: &JsonTransform) -> Self {
        Self {
            operations: config.operations.clone(),
        }
    }

    /// Apply all operations to a JSON value.
    fn apply_operations(&self, mut json: JsonValue, ctx: &TransformContext) -> Result<JsonValue, TransformError> {
        for operation in &self.operations {
            json = self.apply_operation(json, operation, ctx)?;
        }
        Ok(json)
    }

    /// Apply a single operation to a JSON value.
    fn apply_operation(
        &self,
        mut json: JsonValue,
        operation: &JsonOperation,
        ctx: &TransformContext,
    ) -> Result<JsonValue, TransformError> {
        match operation {
            JsonOperation::Set { path, value } => {
                // Interpolate string values
                let interpolated_value = interpolate_json_value(value, ctx);
                set_json_value(&mut json, path, interpolated_value)?;
            }
            JsonOperation::Delete(paths) => {
                for path in paths {
                    delete_json_value(&mut json, path)?;
                }
            }
            JsonOperation::Rename { from, to } => {
                if let Some(value) = get_json_value(&json, from).cloned() {
                    delete_json_value(&mut json, from)?;
                    set_json_value(&mut json, to, value)?;
                }
            }
            JsonOperation::Wrap { path, key } => {
                if let Some(value) = get_json_value(&json, path).cloned() {
                    let wrapped = serde_json::json!({ key: value });
                    set_json_value(&mut json, path, wrapped)?;
                }
            }
            JsonOperation::Merge { path, with } => {
                if let Some(target) = get_json_value_mut(&mut json, path) {
                    if let JsonValue::Object(target_map) = target {
                        if let JsonValue::Object(merge_map) = with {
                            for (k, v) in merge_map {
                                let interpolated = interpolate_json_value(v, ctx);
                                target_map.insert(k.clone(), interpolated);
                            }
                        }
                    }
                }
            }
            JsonOperation::Copy { from, to } => {
                if let Some(value) = get_json_value(&json, from).cloned() {
                    set_json_value(&mut json, to, value)?;
                }
            }
            JsonOperation::Move { from, to } => {
                if let Some(value) = get_json_value(&json, from).cloned() {
                    delete_json_value(&mut json, from)?;
                    set_json_value(&mut json, to, value)?;
                }
            }
        }
        Ok(json)
    }
}

/// Interpolate variables in JSON string values.
fn interpolate_json_value(value: &JsonValue, ctx: &TransformContext) -> JsonValue {
    match value {
        JsonValue::String(s) => JsonValue::String(ctx.interpolate(s)),
        JsonValue::Array(arr) => {
            JsonValue::Array(arr.iter().map(|v| interpolate_json_value(v, ctx)).collect())
        }
        JsonValue::Object(obj) => {
            let mut new_obj = serde_json::Map::new();
            for (k, v) in obj {
                new_obj.insert(k.clone(), interpolate_json_value(v, ctx));
            }
            JsonValue::Object(new_obj)
        }
        other => other.clone(),
    }
}

/// Parse a JSON path into segments.
/// Supports: $.field, $.field.subfield, $.array[0], $.field[0].subfield
fn parse_path(path: &str) -> Vec<PathSegment> {
    let path = path.trim_start_matches("$.");
    let path = path.trim_start_matches('$');

    if path.is_empty() {
        return vec![];
    }

    let mut segments = Vec::new();
    let mut current = String::new();

    let chars: Vec<char> = path.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            '.' => {
                if !current.is_empty() {
                    segments.push(PathSegment::Key(current.clone()));
                    current.clear();
                }
            }
            '[' => {
                if !current.is_empty() {
                    segments.push(PathSegment::Key(current.clone()));
                    current.clear();
                }
                // Parse index
                i += 1;
                let mut idx_str = String::new();
                while i < chars.len() && chars[i] != ']' {
                    idx_str.push(chars[i]);
                    i += 1;
                }
                if let Ok(idx) = idx_str.parse::<usize>() {
                    segments.push(PathSegment::Index(idx));
                }
            }
            ']' => {
                // Skip closing bracket
            }
            c => {
                current.push(c);
            }
        }
        i += 1;
    }

    if !current.is_empty() {
        segments.push(PathSegment::Key(current));
    }

    segments
}

#[derive(Debug, Clone)]
enum PathSegment {
    Key(String),
    Index(usize),
}

/// Get a reference to a JSON value at a path.
fn get_json_value<'a>(json: &'a JsonValue, path: &str) -> Option<&'a JsonValue> {
    let segments = parse_path(path);
    let mut current = json;

    for segment in segments {
        match segment {
            PathSegment::Key(key) => {
                current = current.get(&key)?;
            }
            PathSegment::Index(idx) => {
                current = current.get(idx)?;
            }
        }
    }

    Some(current)
}

/// Get a mutable reference to a JSON value at a path.
fn get_json_value_mut<'a>(json: &'a mut JsonValue, path: &str) -> Option<&'a mut JsonValue> {
    let segments = parse_path(path);
    let mut current = json;

    for segment in segments {
        match segment {
            PathSegment::Key(key) => {
                current = current.get_mut(&key)?;
            }
            PathSegment::Index(idx) => {
                current = current.get_mut(idx)?;
            }
        }
    }

    Some(current)
}

/// Set a JSON value at a path, creating intermediate objects as needed.
fn set_json_value(json: &mut JsonValue, path: &str, value: JsonValue) -> Result<(), TransformError> {
    let segments = parse_path(path);

    if segments.is_empty() {
        *json = value;
        return Ok(());
    }

    let mut current = json;

    for (i, segment) in segments.iter().enumerate() {
        let is_last = i == segments.len() - 1;

        match segment {
            PathSegment::Key(key) => {
                if is_last {
                    if let JsonValue::Object(map) = current {
                        map.insert(key.clone(), value.clone());
                        return Ok(());
                    } else {
                        return Err(TransformError::JsonPath(
                            format!("Cannot set key '{}' on non-object", key)
                        ));
                    }
                } else {
                    // Ensure intermediate object exists
                    if !current.get(key).is_some() {
                        if let JsonValue::Object(map) = current {
                            // Look ahead to see if next segment is index or key
                            let next_segment = &segments[i + 1];
                            let new_value = match next_segment {
                                PathSegment::Index(_) => JsonValue::Array(vec![]),
                                PathSegment::Key(_) => JsonValue::Object(serde_json::Map::new()),
                            };
                            map.insert(key.clone(), new_value);
                        }
                    }
                    current = current.get_mut(key).ok_or_else(|| {
                        TransformError::JsonPath(format!("Path segment '{}' not found", key))
                    })?;
                }
            }
            PathSegment::Index(idx) => {
                if is_last {
                    if let JsonValue::Array(arr) = current {
                        // Extend array if needed
                        while arr.len() <= *idx {
                            arr.push(JsonValue::Null);
                        }
                        arr[*idx] = value.clone();
                        return Ok(());
                    } else {
                        return Err(TransformError::JsonPath(
                            format!("Cannot set index {} on non-array", idx)
                        ));
                    }
                } else {
                    current = current.get_mut(*idx).ok_or_else(|| {
                        TransformError::JsonPath(format!("Index {} out of bounds", idx))
                    })?;
                }
            }
        }
    }

    Ok(())
}

/// Delete a JSON value at a path.
fn delete_json_value(json: &mut JsonValue, path: &str) -> Result<(), TransformError> {
    let segments = parse_path(path);

    if segments.is_empty() {
        return Ok(());
    }

    if segments.len() == 1 {
        match &segments[0] {
            PathSegment::Key(key) => {
                if let JsonValue::Object(map) = json {
                    map.remove(key);
                }
            }
            PathSegment::Index(idx) => {
                if let JsonValue::Array(arr) = json {
                    if *idx < arr.len() {
                        arr.remove(*idx);
                    }
                }
            }
        }
        return Ok(());
    }

    // Navigate to parent
    let parent_segments = &segments[..segments.len() - 1];
    let mut current = json;

    for segment in parent_segments {
        match segment {
            PathSegment::Key(key) => {
                current = match current.get_mut(key) {
                    Some(v) => v,
                    None => return Ok(()), // Path doesn't exist, nothing to delete
                };
            }
            PathSegment::Index(idx) => {
                current = match current.get_mut(*idx) {
                    Some(v) => v,
                    None => return Ok(()),
                };
            }
        }
    }

    // Delete the last segment
    match segments.last().unwrap() {
        PathSegment::Key(key) => {
            if let JsonValue::Object(map) = current {
                map.remove(key);
            }
        }
        PathSegment::Index(idx) => {
            if let JsonValue::Array(arr) = current {
                if *idx < arr.len() {
                    arr.remove(*idx);
                }
            }
        }
    }

    Ok(())
}

#[async_trait]
impl Transformer for JsonTransformer {
    async fn transform(
        &self,
        ctx: &TransformContext,
        body: Option<&[u8]>,
    ) -> Result<TransformResult, TransformError> {
        let body = match body {
            Some(b) if !b.is_empty() => b,
            _ => return Ok(TransformResult::none()),
        };

        // Parse body as JSON
        let json: JsonValue = serde_json::from_slice(body)?;

        // Apply operations
        let transformed = self.apply_operations(json, ctx)?;

        // Serialize back to bytes
        let output = serde_json::to_vec(&transformed)?;

        Ok(TransformResult::with_body(output))
    }

    fn name(&self) -> &'static str {
        "json_transformer"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::RequestInfo;
    use std::collections::HashMap;

    fn make_context() -> TransformContext {
        let request = RequestInfo {
            method: "POST".to_string(),
            path: "/test".to_string(),
            query_string: None,
            query_params: HashMap::new(),
            headers: HashMap::new(),
            client_ip: "127.0.0.1".to_string(),
        };

        let mut captures = HashMap::new();
        captures.insert("version".to_string(), "2".to_string());

        TransformContext::new(request, "test-123".to_string())
            .with_captures(captures)
    }

    #[tokio::test]
    async fn test_set_operation() {
        let config = JsonTransform {
            operations: vec![JsonOperation::Set {
                path: "$.name".to_string(),
                value: serde_json::json!("updated"),
            }],
        };
        let transformer = JsonTransformer::new(&config);

        let body = serde_json::json!({"name": "original", "id": 1});
        let body_bytes = serde_json::to_vec(&body).unwrap();

        let ctx = make_context();
        let result = transformer.transform(&ctx, Some(&body_bytes)).await.unwrap();

        let output: JsonValue = serde_json::from_slice(&result.body.unwrap()).unwrap();
        assert_eq!(output["name"], "updated");
        assert_eq!(output["id"], 1);
    }

    #[tokio::test]
    async fn test_delete_operation() {
        let config = JsonTransform {
            operations: vec![JsonOperation::Delete(vec![
                "$.internal".to_string(),
                "$.debug".to_string(),
            ])],
        };
        let transformer = JsonTransformer::new(&config);

        let body = serde_json::json!({
            "name": "test",
            "internal": "secret",
            "debug": true
        });
        let body_bytes = serde_json::to_vec(&body).unwrap();

        let ctx = make_context();
        let result = transformer.transform(&ctx, Some(&body_bytes)).await.unwrap();

        let output: JsonValue = serde_json::from_slice(&result.body.unwrap()).unwrap();
        assert_eq!(output["name"], "test");
        assert!(output.get("internal").is_none());
        assert!(output.get("debug").is_none());
    }

    #[tokio::test]
    async fn test_rename_operation() {
        let config = JsonTransform {
            operations: vec![JsonOperation::Rename {
                from: "$.old_name".to_string(),
                to: "$.new_name".to_string(),
            }],
        };
        let transformer = JsonTransformer::new(&config);

        let body = serde_json::json!({"old_name": "value", "other": 123});
        let body_bytes = serde_json::to_vec(&body).unwrap();

        let ctx = make_context();
        let result = transformer.transform(&ctx, Some(&body_bytes)).await.unwrap();

        let output: JsonValue = serde_json::from_slice(&result.body.unwrap()).unwrap();
        assert!(output.get("old_name").is_none());
        assert_eq!(output["new_name"], "value");
        assert_eq!(output["other"], 123);
    }

    #[tokio::test]
    async fn test_wrap_operation() {
        let config = JsonTransform {
            operations: vec![JsonOperation::Wrap {
                path: "$".to_string(),
                key: "data".to_string(),
            }],
        };
        let transformer = JsonTransformer::new(&config);

        let body = serde_json::json!({"name": "test", "id": 1});
        let body_bytes = serde_json::to_vec(&body).unwrap();

        let ctx = make_context();
        let result = transformer.transform(&ctx, Some(&body_bytes)).await.unwrap();

        let output: JsonValue = serde_json::from_slice(&result.body.unwrap()).unwrap();
        assert_eq!(output["data"]["name"], "test");
        assert_eq!(output["data"]["id"], 1);
    }

    #[tokio::test]
    async fn test_merge_operation() {
        let config = JsonTransform {
            operations: vec![JsonOperation::Merge {
                path: "$".to_string(),
                with: serde_json::json!({"added": true, "version": "${version}"}),
            }],
        };
        let transformer = JsonTransformer::new(&config);

        let body = serde_json::json!({"name": "test"});
        let body_bytes = serde_json::to_vec(&body).unwrap();

        let ctx = make_context();
        let result = transformer.transform(&ctx, Some(&body_bytes)).await.unwrap();

        let output: JsonValue = serde_json::from_slice(&result.body.unwrap()).unwrap();
        assert_eq!(output["name"], "test");
        assert_eq!(output["added"], true);
        assert_eq!(output["version"], "2"); // Interpolated from captures
    }

    #[tokio::test]
    async fn test_copy_operation() {
        let config = JsonTransform {
            operations: vec![JsonOperation::Copy {
                from: "$.source".to_string(),
                to: "$.destination".to_string(),
            }],
        };
        let transformer = JsonTransformer::new(&config);

        let body = serde_json::json!({"source": "value"});
        let body_bytes = serde_json::to_vec(&body).unwrap();

        let ctx = make_context();
        let result = transformer.transform(&ctx, Some(&body_bytes)).await.unwrap();

        let output: JsonValue = serde_json::from_slice(&result.body.unwrap()).unwrap();
        assert_eq!(output["source"], "value");
        assert_eq!(output["destination"], "value");
    }

    #[tokio::test]
    async fn test_move_operation() {
        let config = JsonTransform {
            operations: vec![JsonOperation::Move {
                from: "$.source".to_string(),
                to: "$.destination".to_string(),
            }],
        };
        let transformer = JsonTransformer::new(&config);

        let body = serde_json::json!({"source": "value", "other": 123});
        let body_bytes = serde_json::to_vec(&body).unwrap();

        let ctx = make_context();
        let result = transformer.transform(&ctx, Some(&body_bytes)).await.unwrap();

        let output: JsonValue = serde_json::from_slice(&result.body.unwrap()).unwrap();
        assert!(output.get("source").is_none());
        assert_eq!(output["destination"], "value");
        assert_eq!(output["other"], 123);
    }

    #[tokio::test]
    async fn test_nested_path() {
        let config = JsonTransform {
            operations: vec![JsonOperation::Set {
                path: "$.user.profile.name".to_string(),
                value: serde_json::json!("updated"),
            }],
        };
        let transformer = JsonTransformer::new(&config);

        let body = serde_json::json!({
            "user": {
                "profile": {
                    "name": "original",
                    "age": 30
                }
            }
        });
        let body_bytes = serde_json::to_vec(&body).unwrap();

        let ctx = make_context();
        let result = transformer.transform(&ctx, Some(&body_bytes)).await.unwrap();

        let output: JsonValue = serde_json::from_slice(&result.body.unwrap()).unwrap();
        assert_eq!(output["user"]["profile"]["name"], "updated");
        assert_eq!(output["user"]["profile"]["age"], 30);
    }

    #[tokio::test]
    async fn test_array_index() {
        let config = JsonTransform {
            operations: vec![JsonOperation::Set {
                path: "$.items[1]".to_string(),
                value: serde_json::json!("updated"),
            }],
        };
        let transformer = JsonTransformer::new(&config);

        let body = serde_json::json!({"items": ["a", "b", "c"]});
        let body_bytes = serde_json::to_vec(&body).unwrap();

        let ctx = make_context();
        let result = transformer.transform(&ctx, Some(&body_bytes)).await.unwrap();

        let output: JsonValue = serde_json::from_slice(&result.body.unwrap()).unwrap();
        assert_eq!(output["items"][0], "a");
        assert_eq!(output["items"][1], "updated");
        assert_eq!(output["items"][2], "c");
    }

    #[tokio::test]
    async fn test_interpolation_in_set() {
        let config = JsonTransform {
            operations: vec![JsonOperation::Set {
                path: "$.api_version".to_string(),
                value: serde_json::json!("v${version}"),
            }],
        };
        let transformer = JsonTransformer::new(&config);

        let body = serde_json::json!({"name": "test"});
        let body_bytes = serde_json::to_vec(&body).unwrap();

        let ctx = make_context();
        let result = transformer.transform(&ctx, Some(&body_bytes)).await.unwrap();

        let output: JsonValue = serde_json::from_slice(&result.body.unwrap()).unwrap();
        assert_eq!(output["api_version"], "v2");
    }

    #[tokio::test]
    async fn test_multiple_operations() {
        let config = JsonTransform {
            operations: vec![
                JsonOperation::Delete(vec!["$.internal".to_string()]),
                JsonOperation::Rename {
                    from: "$.old".to_string(),
                    to: "$.new".to_string(),
                },
                JsonOperation::Set {
                    path: "$.meta.version".to_string(),
                    value: serde_json::json!("2.0"),
                },
            ],
        };
        let transformer = JsonTransformer::new(&config);

        let body = serde_json::json!({
            "name": "test",
            "old": "value",
            "internal": "secret",
            "meta": {}
        });
        let body_bytes = serde_json::to_vec(&body).unwrap();

        let ctx = make_context();
        let result = transformer.transform(&ctx, Some(&body_bytes)).await.unwrap();

        let output: JsonValue = serde_json::from_slice(&result.body.unwrap()).unwrap();
        assert_eq!(output["name"], "test");
        assert!(output.get("internal").is_none());
        assert!(output.get("old").is_none());
        assert_eq!(output["new"], "value");
        assert_eq!(output["meta"]["version"], "2.0");
    }

    #[test]
    fn test_parse_path() {
        let segments = parse_path("$.user.profile.name");
        assert_eq!(segments.len(), 3);

        let segments = parse_path("$.items[0].name");
        assert_eq!(segments.len(), 3);

        let segments = parse_path("$");
        assert_eq!(segments.len(), 0);
    }
}
