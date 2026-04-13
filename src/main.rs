use ax_extract::ConnectInfo;
use axum::{
	extract::{self as ax_extract, State},
	http::{HeaderMap, StatusCode},
	response::{sse::{Event, KeepAlive}, Sse},
	routing::get,
	Router,
};
use clap::Parser;
use futures_util::stream::{self, Stream};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use yescrypt::password_hash::PasswordVerifier;
use yescrypt::Yescrypt;

#[derive(Deserialize, Clone, Debug)]
struct GlobalConfig {
	#[serde(default = "default_auth_header")]
	auth_header: String,
	#[serde(default = "default_timeout")]
	timeout: u64,
}

fn default_auth_header() -> String {
	"x-api-key".to_string()
}

fn default_timeout() -> u64 {
	900
}

impl Default for GlobalConfig {
	fn default() -> Self {
		Self {
			auth_header: default_auth_header(),
			timeout: default_timeout(),
		}
	}
}

#[derive(Deserialize, Clone, Debug)]
struct RouteConfig {
	shell: String,
	args: Vec<String>,
	keys: String,
}

#[derive(Deserialize, Clone, Debug)]
struct Config {
	#[serde(default)]
	global: GlobalConfig,
	#[serde(flatten)]
	routes: HashMap<String, RouteConfig>,
}

#[derive(Serialize, Debug)]
struct OutputLine {
	r#type: String, // "stdout" or "stderr"
	line: String,
}

struct AppState {
	config: Config,
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
}

fn main() {
	let cli = Cli::parse();
	run(cli);
}

#[tokio::main]
async fn run(cli: Cli) {

	tracing_subscriber::registry()
		.with(tracing_subscriber::fmt::layer())
		.with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "cause=debug,tower_http=debug,axum::rejection=trace".into()))
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

	let state = Arc::new(AppState { config: config.clone() });

	let mut router = Router::new();

	for (route_name, _) in &config.routes {
		let route_path = format!("/{}", route_name);
		info!("[+] route: {}", route_path);
		let route_name_cloned = route_name.clone();
		router = router.route(
			&route_path,
			get(move |headers, connect_info, state| handle_route(route_name_cloned, headers, connect_info, state)),
		);
	}

	let router = router.with_state(state);

	let addr_str = format!("{}:{}", cli.address, cli.port);
	let addr: SocketAddr = addr_str.parse().expect("Invalid address or port");

	info!("[+] listening on {}", addr);
	let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
	axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}

async fn handle_route(
	route_name: String,
	headers: HeaderMap,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	State(state): State<Arc<AppState>>,
) -> Result<Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>>, (StatusCode, String)> {
	let x_forwarded_for = headers
		.get("X-Forwarded-For")
		.and_then(|v| v.to_str().ok())
		.unwrap_or("-");

	info!(
		"[+] start: {}: client_ip: {}, x_forwarded_for: {}",
		route_name, addr, x_forwarded_for
	);

	let route_config = state.config.routes.get(&route_name).ok_or((
		StatusCode::NOT_FOUND,
		format!("Route {} not found", route_name),
	))?;

	let auth_header_name = &state.config.global.auth_header;
	let auth_key = headers
		.get(auth_header_name)
		.and_then(|h| h.to_str().ok())
		.ok_or((StatusCode::UNAUTHORIZED, "Missing auth header".to_string()))?;

	if !authenticate(auth_key, &route_config.keys).await {
		return Err((StatusCode::UNAUTHORIZED, "Invalid auth key".to_string()));
	}

	let mut child = Command::new(&route_config.shell)
		.args(&route_config.args)
		.stdout(std::process::Stdio::piped())
		.stderr(std::process::Stdio::piped())
		.spawn()
		.map_err(|e| {
			error!("[!] failed to spawn: {}: {}", route_name, e);
			(StatusCode::INTERNAL_SERVER_ERROR, "Failed to execute shell".to_string())
		})?;

	let stdout = child.stdout.take().unwrap();
	let stderr = child.stderr.take().unwrap();

	let timeout_duration = Duration::from_secs(state.config.global.timeout);

	tokio::spawn(async move {
		match tokio::time::timeout(timeout_duration, child.wait()).await {
			Ok(status) => {
				info!("[+] exit: {}: {:?}", route_name, status);
			}
			Err(_) => {
				error!("[!] timeout, killing: {}", route_name);
				let _ = child.kill().await;
			}
		}
	});

	let stdout_reader = BufReader::new(stdout).lines();
	let stderr_reader = BufReader::new(stderr).lines();

	let stdout_stream = futures_util::stream::unfold(stdout_reader, |mut reader| async {
		match reader.next_line().await {
			Ok(Some(line)) => Some((
				Ok(Event::default().json_data(OutputLine {
					r#type: "stdout".to_string(),
					line,
				}).unwrap()),
				reader,
			)),
			_ => None,
		}
	});

	let stderr_stream = futures_util::stream::unfold(stderr_reader, |mut reader| async {
		match reader.next_line().await {
			Ok(Some(line)) => Some((
				Ok(Event::default().json_data(OutputLine {
					r#type: "stderr".to_string(),
					line,
				}).unwrap()),
				reader,
			)),
			_ => None,
		}
	});

	let combined_stream = stream::select(stdout_stream, stderr_stream);

	Ok(Sse::new(combined_stream).keep_alive(KeepAlive::default()))
}

async fn authenticate(key: &str, keys_file: &str) -> bool {
	let content = match tokio::fs::read_to_string(keys_file).await {
		Ok(c) => c,
		Err(e) => {
			error!("[!] failed to read keys file {}: {}", keys_file, e);
			return false;
		}
	};

	for line in content.lines() {
		let hash = line.trim();
		if hash.is_empty() {
			continue;
		}

		if Yescrypt::default().verify_password(key.as_bytes(), hash).is_ok() {
			return true;
		}
	}

	false
}
