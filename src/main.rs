//! Sentinel Transform Agent CLI entry point.
//!
//! Request/Response transformation agent for Sentinel proxy using v2 protocol.

use anyhow::{Context, Result};
use clap::Parser;
use sentinel_agent_protocol::v2::GrpcAgentServerV2;
use sentinel_agent_transform::{TransformAgent, TransformConfig};
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "sentinel-agent-transform")]
#[command(author, version, about = "Request/Response transformation agent for Sentinel")]
struct Args {
    /// Configuration file path (YAML or JSON)
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Template directory path
    #[arg(long, default_value = "/etc/sentinel/templates")]
    template_dir: PathBuf,

    /// gRPC address to listen on (e.g., "0.0.0.0:50051").
    /// Defaults to "0.0.0.0:50051" if not specified.
    #[arg(long, env = "TRANSFORM_GRPC_ADDRESS")]
    grpc_address: Option<String>,

    /// Output logs as JSON
    #[arg(long)]
    json_logs: bool,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Print example configuration and exit.
    #[arg(long)]
    example_config: bool,

    /// Validate configuration and exit.
    #[arg(long)]
    validate: bool,
}

fn print_example_config() {
    let example = r#"# Transform Agent Configuration Example
version: "1"

settings:
  # Maximum body size to buffer for transformation (bytes)
  max_body_size: 10485760  # 10MB
  # Template directory path
  template_dir: "/etc/sentinel/templates"
  # Enable template caching
  cache_templates: true
  # Enable debug headers (X-Transform-Rule, X-Transform-Time)
  debug_headers: false
  # Default timeout for transformations (ms)
  timeout_ms: 100

rules:
  # API v1 to v2 rewrite example
  - name: "api-v1-rewrite"
    description: "Rewrite API v1 paths to v2"
    enabled: true
    priority: 100
    match:
      path:
        pattern: "^/api/v1/(.*)$"
        type: regex
    request:
      url:
        rewrite: "/api/v2/${1}"
        preserve_query: true

  # Add CORS headers example
  - name: "add-cors-headers"
    description: "Add CORS headers to responses"
    enabled: true
    priority: 50
    match:
      path:
        pattern: "^/api/.*"
        type: regex
    response:
      headers:
        set:
          - name: "Access-Control-Allow-Origin"
            value: "*"
          - name: "Access-Control-Allow-Methods"
            value: "GET, POST, PUT, DELETE, OPTIONS"
"#;
    println!("{}", example);
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&args.log_level));

    if args.json_logs {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer())
            .init();
    }

    // Print example config if requested
    if args.example_config {
        print_example_config();
        return Ok(());
    }

    // Load configuration
    let mut config = if let Some(config_path) = &args.config {
        let content = std::fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read config file: {}", config_path.display()))?;
        if config_path
            .extension()
            .is_some_and(|e| e == "yaml" || e == "yml")
        {
            serde_yaml::from_str(&content)?
        } else {
            serde_json::from_str(&content)?
        }
    } else {
        TransformConfig::default()
    };

    // Override template directory from CLI
    config.settings.template_dir = args.template_dir.to_string_lossy().to_string();

    // Validate only if requested
    if args.validate {
        // Create agent to validate configuration
        let _agent = TransformAgent::new(config)?;
        info!("Configuration is valid");
        return Ok(());
    }

    // Create agent
    let agent = TransformAgent::new(config)?;

    info!("Transform agent initialized");

    // Determine gRPC address
    let grpc_addr = args
        .grpc_address
        .unwrap_or_else(|| "0.0.0.0:50051".to_string());

    info!(
        config = ?args.config,
        grpc_address = %grpc_addr,
        "Starting Sentinel Transform Agent (gRPC v2)"
    );

    let addr = grpc_addr
        .parse()
        .context("Invalid gRPC address format (expected host:port)")?;

    let server = GrpcAgentServerV2::new("transform", Box::new(agent));

    info!("Transform agent ready and listening on gRPC");

    server
        .run(addr)
        .await
        .context("Failed to run Transform Agent gRPC server")?;

    Ok(())
}
