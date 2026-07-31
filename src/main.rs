use ax_extract::ConnectInfo;
use axum::{
	Router,
	extract::{self as ax_extract, State},
	http::{HeaderMap, StatusCode},
	response::{
		Sse,
		sse::{Event, KeepAlive},
	},
	routing::get,
};
use clap::Parser;
use futures_util::stream::{self, Stream};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use yescrypt::Yescrypt;
use yescrypt::password_hash::PasswordVerifier;

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
	#[serde(default = "default_concurrency")]
	concurrency: usize,
}

fn default_concurrency() -> usize {
	1
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

struct Keys {
	hashes: Vec<String>,
}

impl Keys {
	fn from_file(path: &str) -> Result<Self, String> {
		let content = fs::read_to_string(path)
			.map_err(|e| format!("failed to read keys file {}: {}", path, e))?;
		let mut hashes = Vec::new();
		for line in content.lines() {
			let hash = line.trim().to_string();
			if hash.is_empty() {
				continue;
			}
			hashes.push(hash);
		}
		Ok(Self { hashes })
	}

	fn verify(&self, key: &str) -> bool {
		for hash in &self.hashes {
			if Yescrypt::default()
				.verify_password(key.as_bytes(), hash.as_str())
				.is_ok()
			{
				return true;
			}
		}
		false
	}
}

struct AppState {
	config: Config,
	keys: HashMap<String, Keys>,
	semaphores: HashMap<String, Arc<Semaphore>>,
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

	let mut semaphores = HashMap::new();
	for (name, route) in &config.routes {
		semaphores.insert(name.clone(), Arc::new(Semaphore::new(route.concurrency)));
	}

	let state = Arc::new(AppState {
		config: config.clone(),
		keys,
		semaphores,
	});

	let mut router = Router::new();

	for (route_name, _) in &config.routes {
		let route_path = format!("/{}", route_name);
		let semaphore = state.semaphores.get(route_name).unwrap().clone();
		info!("[+] route: {}", route_path);
		let route_name_cloned = route_name.clone();
		router = router.route(
			&route_path,
			get(move |headers, connect_info, state| {
				handle_route(route_name_cloned, headers, connect_info, state, semaphore)
			}),
		);
	}

	let router = router.with_state(state);

	let addr_str = format!("{}:{}", cli.address, cli.port);
	let addr: SocketAddr = addr_str.parse().expect("Invalid address or port");

	info!("[+] listening on {}", addr);
	let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
	axum::serve(
		listener,
		router.into_make_service_with_connect_info::<SocketAddr>(),
	)
	.await
	.unwrap();
}

async fn handle_route(
	route_name: String,
	headers: HeaderMap,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	State(state): State<Arc<AppState>>,
	semaphore: Arc<Semaphore>,
) -> Result<Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>>, (StatusCode, String)>
{
	let x_forwarded_for = headers
		.get("X-Forwarded-For")
		.and_then(|v| v.to_str().ok())
		.unwrap_or("-");

	info!(
		"[+] request: {}: client_ip: {}, x_forwarded_for: {}",
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

	let route_keys = state.keys.get(&route_name).ok_or((
		StatusCode::INTERNAL_SERVER_ERROR,
		"Keys not loaded for route".to_string(),
	))?;

	if !route_keys.verify(auth_key) {
		return Err((StatusCode::UNAUTHORIZED, "Invalid auth key".to_string()));
	}

	let permit = match semaphore.try_acquire_owned() {
		Ok(p) => p,
		Err(_) => {
			warn!("[!] route concurrency limit reached: {}", route_name);
			return Err((
				StatusCode::SERVICE_UNAVAILABLE,
				"Route concurrency limit reached".to_string(),
			));
		}
	};

	let mut child = Command::new(&route_config.shell)
		.args(&route_config.args)
		.stdout(std::process::Stdio::piped())
		.stderr(std::process::Stdio::piped())
		.spawn()
		.map_err(|e| {
			error!("[!] failed to spawn: {}: {}", route_name, e);
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				"Failed to execute shell".to_string(),
			)
		})?;

	info!(
		"[+] spawn: {}: client_ip: {}, x_forwarded_for: {}",
		route_name, addr, x_forwarded_for
	);
	let stdout = child.stdout.take().unwrap();
	let stderr = child.stderr.take().unwrap();

	let timeout_duration = Duration::from_secs(state.config.global.timeout);

	tokio::spawn(async move {
		match tokio::time::timeout(timeout_duration, child.wait()).await {
			Ok(Ok(status)) => {
				info!(
					"[+] exit: {}: return: {:?}",
					route_name,
					status.code().unwrap_or(-1)
				);
			}
			Ok(Err(e)) => {
				error!("[!] failed to wait on child: {}: {}", route_name, e);
			}
			Err(_) => {
				error!("[!] timeout, killing: {}", route_name);
				let _ = child.kill().await;
			}
		}
		drop(permit);
	});

	let stdout_reader = BufReader::new(stdout).lines();
	let stderr_reader = BufReader::new(stderr).lines();

	let stdout_stream = futures_util::stream::unfold(stdout_reader, |mut reader| async {
		match reader.next_line().await {
			Ok(Some(line)) => Some((
				Ok(Event::default()
					.json_data(OutputLine {
						r#type: "stdout".to_string(),
						line,
					})
					.unwrap()),
				reader,
			)),
			_ => None,
		}
	});

	let stderr_stream = futures_util::stream::unfold(stderr_reader, |mut reader| async {
		match reader.next_line().await {
			Ok(Some(line)) => Some((
				Ok(Event::default()
					.json_data(OutputLine {
						r#type: "stderr".to_string(),
						line,
					})
					.unwrap()),
				reader,
			)),
			_ => None,
		}
	});

	let combined_stream = stream::select(stdout_stream, stderr_stream);

	Ok(Sse::new(combined_stream).keep_alive(KeepAlive::default()))
}
