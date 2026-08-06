use anyhow::Context;
use axum::{
	Router,
	routing::{get, post},
};
use clap::Parser;
use std::io::IsTerminal;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod auth;
mod config;
mod executor;
mod handler;
mod net;
mod rate_limit;
mod route_state;

#[cfg(test)]
mod tests;

use config::Config;
use handler::AppState;
use rate_limit::TrustedProxyKeyExtractor;

#[derive(clap::ValueEnum, Clone, Debug, Default)]
enum LogFormat {
	#[default]
	Text,
	Json,
}

impl std::fmt::Display for LogFormat {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			LogFormat::Text => write!(f, "text"),
			LogFormat::Json => write!(f, "json"),
		}
	}
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
	/// Path to the configuration file
	#[arg(short, long, default_value = "cause.toml")]
	config: String,

	/// Address to listen on
	#[arg(short, long, default_value = "127.0.0.1")]
	address: String,

	/// Port to listen on
	#[arg(short, long, default_value_t = 3000)]
	port: u16,

	/// Log format: text or json. Defaults to json when stdout is not a terminal.
	#[arg(long, default_value_t)]
	log_format: LogFormat,

	/// Log level filter (e.g. cause=debug,axum::rejection=trace)
	#[arg(long)]
	log_level: Option<String>,
}

fn init_logging(cli: &Cli) {
	let filter = match &cli.log_level {
		Some(level) => tracing_subscriber::EnvFilter::new(level.as_str()),
		None => tracing_subscriber::EnvFilter::try_from_default_env()
			.unwrap_or_else(|_| "cause=debug,axum::rejection=trace".into()),
	};

	let is_tty = std::io::stdout().is_terminal();
	let format = match cli.log_format {
		LogFormat::Json => LogFormat::Json,
		LogFormat::Text if is_tty => LogFormat::Text,
		LogFormat::Text => LogFormat::Json,
	};

	match format {
		LogFormat::Json => {
			let registry = tracing_subscriber::registry().with(filter);
			let layer = tracing_subscriber::fmt::layer()
				.json()
				.flatten_event(true)
				.with_current_span(true)
				.with_span_list(false);
			registry.with(layer).init();
		}
		LogFormat::Text => {
			tracing_subscriber::registry()
				.with(filter)
				.with(tracing_subscriber::fmt::layer())
				.init();
		}
	}
}

async fn shutdown_signal() {
	let sigint = async {
		signal::ctrl_c().await.ok();
	};

	let sigterm = async {
		match signal::unix::signal(signal::unix::SignalKind::terminate()) {
			Ok(mut s) => s.recv().await,
			Err(e) => {
				warn!(error = %e, "failed to register SIGTERM handler, falling back to Ctrl-C only");
				std::future::pending().await
			}
		}
	};

	tokio::select! {
		_ = sigint => {}
		_ = sigterm => {}
	}
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	let cli = Cli::parse();
	init_logging(&cli);

	let content = tokio::fs::read_to_string(&cli.config)
		.await
		.with_context(|| format!("failed to read config file {}", cli.config))?;
	let config: Config = toml::from_str(&content).context("failed to parse config file")?;

	config.validate().context("invalid config")?;

	let state = AppState::from_config(config).await?;

	for route_name in state.config.routes.keys() {
		info!(route = %route_name, "route registered");
	}

	let global = &state.config.global;
	let failure_tracker = state.failure_tracker.clone();
	let trusted_proxies = global.trusted_proxies.clone();
	let rate_limit_per_second = global.rate_limit_per_second;
	let rate_limit_burst = global.rate_limit_burst;
	let cleanup_interval = Duration::from_secs(global.block_duration_secs.get());

	let router = Router::new()
		.route("/", get(handler::health))
		.route("/{route}", post(handler::handle_route))
		.with_state(Arc::new(state));

	let router = rate_limit::rate_limited(
		router,
		TrustedProxyKeyExtractor { trusted_proxies },
		failure_tracker,
		rate_limit_per_second,
		rate_limit_burst,
		cleanup_interval,
	)?;

	let ip: IpAddr = cli
		.address
		.parse()
		.with_context(|| format!("invalid address {}", cli.address))?;
	let addr = SocketAddr::new(ip, cli.port);

	info!(%addr, "listening");
	let listener = tokio::net::TcpListener::bind(addr)
		.await
		.with_context(|| format!("failed to bind to {}", addr))?;

	axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
		.with_graceful_shutdown(shutdown_signal())
		.await
		.context("server error")?;

	Ok(())
}
