//! Sentinel Transform Agent CLI entry point.

use anyhow::Result;
use clap::Parser;
use sentinel_agent_sdk::AgentRunner;
use sentinel_agent_transform::{TransformAgent, TransformConfig};
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "sentinel-agent-transform")]
#[command(author, version, about = "Request/Response transformation agent for Sentinel")]
struct Args {
    /// Unix socket path for agent communication
    #[arg(short, long, default_value = "/tmp/sentinel-transform.sock")]
    socket: PathBuf,

    /// Configuration file path (YAML or JSON)
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Template directory path
    #[arg(long, default_value = "/etc/sentinel/templates")]
    template_dir: PathBuf,

    /// Output logs as JSON
    #[arg(long)]
    json_logs: bool,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,
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

    info!(
        socket = %args.socket.display(),
        config = ?args.config,
        "Starting Sentinel Transform Agent"
    );

    // Load configuration
    let mut config = if let Some(config_path) = &args.config {
        let content = std::fs::read_to_string(config_path)?;
        if config_path.extension().map_or(false, |e| e == "yaml" || e == "yml") {
            serde_yaml::from_str(&content)?
        } else {
            serde_json::from_str(&content)?
        }
    } else {
        TransformConfig::default()
    };

    // Override template directory from CLI
    config.settings.template_dir = args.template_dir.to_string_lossy().to_string();

    // Create agent
    let agent = TransformAgent::new(config)?;

    info!("Transform agent initialized");

    // Run agent
    let mut runner = AgentRunner::new(agent)
        .with_name("transform")
        .with_socket(&args.socket);

    if args.json_logs {
        runner = runner.with_json_logs();
    }

    runner.run().await?;

    Ok(())
}
