//! Request and response transformers.

pub mod header;
pub mod json;
pub mod url;

pub use self::header::HeaderTransformer;
pub use self::json::JsonTransformer;
pub use self::url::UrlTransformer;

use crate::context::TransformContext;
use async_trait::async_trait;

/// Result of a transformation.
#[derive(Debug, Clone, Default)]
pub struct TransformResult {
    /// New body content (if modified)
    pub body: Option<Vec<u8>>,
    /// Headers to add
    pub add_headers: Vec<(String, String)>,
    /// Headers to remove
    pub remove_headers: Vec<String>,
    /// New URL (for request transforms)
    pub new_url: Option<String>,
    /// New HTTP method (for request transforms)
    pub new_method: Option<String>,
    /// New status code (for response transforms)
    pub new_status: Option<u16>,
}

impl TransformResult {
    /// Create an empty result (no changes).
    pub fn none() -> Self {
        Self::default()
    }

    /// Create a result with a new body.
    pub fn with_body(body: Vec<u8>) -> Self {
        Self {
            body: Some(body),
            ..Default::default()
        }
    }

    /// Create a result with a new URL.
    pub fn with_url(url: String) -> Self {
        Self {
            new_url: Some(url),
            ..Default::default()
        }
    }

    /// Add a header to the result.
    pub fn add_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.add_headers.push((name.into(), value.into()));
        self
    }

    /// Remove a header from the result.
    pub fn remove_header(mut self, name: impl Into<String>) -> Self {
        self.remove_headers.push(name.into());
        self
    }

    /// Set the new URL.
    pub fn set_url(mut self, url: impl Into<String>) -> Self {
        self.new_url = Some(url.into());
        self
    }

    /// Set the new method.
    pub fn set_method(mut self, method: impl Into<String>) -> Self {
        self.new_method = Some(method.into());
        self
    }

    /// Set the new status.
    pub fn set_status(mut self, status: u16) -> Self {
        self.new_status = Some(status);
        self
    }

    /// Set the new body.
    pub fn set_body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    /// Merge another result into this one.
    pub fn merge(mut self, other: TransformResult) -> Self {
        if other.body.is_some() {
            self.body = other.body;
        }
        self.add_headers.extend(other.add_headers);
        self.remove_headers.extend(other.remove_headers);
        if other.new_url.is_some() {
            self.new_url = other.new_url;
        }
        if other.new_method.is_some() {
            self.new_method = other.new_method;
        }
        if other.new_status.is_some() {
            self.new_status = other.new_status;
        }
        self
    }

    /// Check if any transformations were made.
    pub fn has_changes(&self) -> bool {
        self.body.is_some()
            || !self.add_headers.is_empty()
            || !self.remove_headers.is_empty()
            || self.new_url.is_some()
            || self.new_method.is_some()
            || self.new_status.is_some()
    }
}

/// Trait for implementing transformers.
#[async_trait]
pub trait Transformer: Send + Sync {
    /// Apply transformation.
    async fn transform(
        &self,
        ctx: &TransformContext,
        body: Option<&[u8]>,
    ) -> Result<TransformResult, TransformError>;

    /// Transformer name for logging.
    fn name(&self) -> &'static str;
}

/// Errors during transformation.
#[derive(Debug, thiserror::Error)]
pub enum TransformError {
    #[error("JSON parse error: {0}")]
    JsonParse(#[from] serde_json::Error),

    #[error("JSON path error: {0}")]
    JsonPath(String),

    #[error("XML parse error: {0}")]
    XmlParse(String),

    #[error("Template error: {0}")]
    Template(String),

    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),

    #[error("Variable not found: {0}")]
    VariableNotFound(String),

    #[error("Body too large: {0} bytes")]
    BodyTooLarge(usize),

    #[error("Invalid UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("Transformation failed: {0}")]
    Other(String),
}

/// Collection of transformers to apply.
pub struct TransformerChain {
    transformers: Vec<Box<dyn Transformer>>,
}

impl TransformerChain {
    /// Create a new empty chain.
    pub fn new() -> Self {
        Self {
            transformers: Vec::new(),
        }
    }

    /// Add a transformer to the chain.
    pub fn add<T: Transformer + 'static>(mut self, transformer: T) -> Self {
        self.transformers.push(Box::new(transformer));
        self
    }

    /// Apply all transformers in order.
    pub async fn apply(
        &self,
        ctx: &TransformContext,
        body: Option<&[u8]>,
    ) -> Result<TransformResult, TransformError> {
        let mut result = TransformResult::none();
        let mut current_body = body.map(|b| b.to_vec());

        for transformer in &self.transformers {
            let body_ref = current_body.as_deref();
            let transform_result = transformer.transform(ctx, body_ref).await?;

            // Update body if transformer modified it
            if let Some(ref new_body) = transform_result.body {
                current_body = Some(new_body.clone());
            }

            result = result.merge(transform_result);
        }

        // Set final body
        if current_body.is_some() && result.body.is_none() && body.is_some() {
            // Body was potentially modified by chain
            result.body = current_body;
        }

        Ok(result)
    }

    /// Check if the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.transformers.is_empty()
    }
}

impl Default for TransformerChain {
    fn default() -> Self {
        Self::new()
    }
}
