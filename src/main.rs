use axum::{Router, routing::post};
use clap::Parser;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod auth;
mod config;
mod handler;

#[cfg(test)]
mod tests;

use auth::{FailureTracker, Keys};
use config::{Config, validate_route_name};
use handler::{AppState, rate_limited};

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
}

#[tokio::main]
async fn main() {
	let cli = Cli::parse();
	tracing_subscriber::registry()
		.with(tracing_subscriber::fmt::layer())
		.with(
			tracing_subscriber::EnvFilter::try_from_default_env()
				.unwrap_or_else(|_| "cause=debug,axum::rejection=trace".into()),
		)
		.init();

	let config_path = &cli.config;

	let config_content = match tokio::fs::read_to_string(config_path).await {
		Ok(c) => c,
		Err(e) => {
			error!("[!] failed to read config file {}: {}", config_path, e);
			std::process::exit(1);
		}
	};

	let config: Config = match toml::from_str(&config_content) {
		Ok(c) => c,
		Err(e) => {
			error!("[!] failed to parse config file: {}", e);
			std::process::exit(1);
		}
	};

	for name in config.routes.keys() {
		if !validate_route_name(name) {
			error!("[!] invalid route name: {}", name);
			std::process::exit(1);
		}
	}

	let mut keys = HashMap::new();
	for (name, route) in &config.routes {
		match Keys::from_file(&route.keys) {
			Ok(parsed) => {
				info!("[+] loaded keys for route: {}", name);
				keys.insert(name.clone(), parsed);
			}
			Err(e) => {
				error!("[!] {}", e);
				std::process::exit(1);
			}
		}
	}

	for (name, route) in &config.routes {
		let shell_path = std::path::Path::new(&route.shell);
		if !shell_path.exists() {
			error!("[!] shell not found for route {}: {}", name, route.shell);
			std::process::exit(1);
		}
		let metadata = match tokio::fs::metadata(shell_path).await {
			Ok(m) => m,
			Err(e) => {
				error!("[!] cannot stat shell for route {}: {}", name, e);
				std::process::exit(1);
			}
		};
		if !metadata.is_file() {
			error!("[!] shell for route {} is not a file: {}", name, route.shell);
			std::process::exit(1);
		}
		let keys_path = std::path::Path::new(&route.keys);
		if !keys_path.exists() {
			error!("[!] keys file not found for route {}: {}", name, route.keys);
			std::process::exit(1);
		}
	}

	let mut semaphores = HashMap::new();
	for (name, route) in &config.routes {
		semaphores.insert(name.clone(), Arc::new(Semaphore::new(route.concurrency)));
	}

	let auth_semaphore = Arc::new(Semaphore::new(4));
	let failure_tracker = Arc::new(FailureTracker::new(10, Duration::from_secs(600)));

	let state = Arc::new(AppState::new(
		config.clone(),
		keys,
		semaphores,
		auth_semaphore,
		failure_tracker,
	));

	let mut router = Router::new();

	for route_name in config.routes.keys() {
		info!("[+] route: /{}", route_name);
	}

	router = router.route("/{route}", post(handler::handle_route));

	let failure_tracker = state.failure_tracker.clone();
	let router = router.with_state(state);

	let addr_str = format!("{}:{}", cli.address, cli.port);
	let addr: SocketAddr = match addr_str.parse() {
		Ok(a) => a,
		Err(e) => {
			error!("[!] invalid address or port {}: {}", addr_str, e);
			std::process::exit(1);
		}
	};

	info!("[+] listening on {}", addr);
	let listener = match tokio::net::TcpListener::bind(addr).await {
		Ok(l) => l,
		Err(e) => {
			error!("[!] failed to bind to {}: {}", addr, e);
			std::process::exit(1);
		}
	};

	let router = if config.global.trusted_proxies.is_empty() {
		rate_limited(
			router,
			tower_governor::key_extractor::PeerIpKeyExtractor,
			failure_tracker,
		)
	} else {
		rate_limited(
			router,
			tower_governor::key_extractor::SmartIpKeyExtractor,
			failure_tracker,
		)
	};

	match axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await {
		Ok(()) => {}
		Err(e) => {
			error!("[!] server error: {}", e);
			std::process::exit(1);
		}
	}
}
