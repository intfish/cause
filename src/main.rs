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
use std::{
	collections::HashMap,
	fs,
	net::{IpAddr, SocketAddr},
	sync::{Arc, Mutex},
	time::{Duration, Instant},
};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::Semaphore;
use tower_governor::GovernorLayer;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use yescrypt::Yescrypt;
use yescrypt::password_hash::PasswordVerifier;

/// Resolves the effective client IP from the TCP peer address and proxy headers.
/// X-Forwarded-For => X-Real-IP => TCP peer address
fn resolve_client_ip(addr: SocketAddr, headers: &HeaderMap, trusted_proxies: &[IpAddr]) -> IpAddr {
	if trusted_proxies.contains(&addr.ip()) {
		if let Some(ip) = headers
			.get("x-forwarded-for")
			.and_then(|v| v.to_str().ok())
			.and_then(|s| {
				s.split(',')
					.rev()
					.filter_map(|p| p.trim().parse::<IpAddr>().ok())
					.find(|ip| !trusted_proxies.contains(ip))
			}) {
			return ip;
		}
		if let Some(ip) = headers
			.get("x-real-ip")
			.and_then(|v| v.to_str().ok())
			.and_then(|s| s.trim().parse::<IpAddr>().ok())
		{
			return ip;
		}
	}
	addr.ip()
}

#[derive(Deserialize, Clone, Debug)]
struct GlobalConfig {
	#[serde(default = "default_auth_header")]
	auth_header: String,
	#[serde(default = "default_timeout")]
	timeout: u64,
	#[serde(default)]
	trusted_proxies: Vec<IpAddr>,
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
			trusted_proxies: Vec::new(),
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
	r#type: String,
	line: String,
}

#[derive(Clone)]
struct Keys {
	// key_id -> list of yescrypt hashes (tolerates ID collisions)
	hashes: HashMap<String, Vec<String>>,
}

impl Keys {
	fn from_file(path: &str) -> Result<Self, String> {
		let content = fs::read_to_string(path).map_err(|e| format!("failed to read keys file {}: {}", path, e))?;
		let mut hashes: HashMap<String, Vec<String>> = HashMap::new();
		for line in content.lines() {
			let line = line.trim();
			if line.is_empty() {
				continue;
			}
			// require keyid:hash format
			let (key_id, hash) = line
				.split_once(':')
				.ok_or_else(|| format!("malformed line in {}: (no ':'): {}", path, line))?;
			let key_id = key_id.to_string();
			let hash = hash.to_string();
			hashes.entry(key_id).or_default().push(hash);
		}
		Ok(Self { hashes })
	}

	fn verify(&self, key: &str) -> bool {
		let (key_id, secret) = match key.split_once('.') {
			Some((id, secret)) => (id, secret),
			None => return false,
		};
		let hash_list = match self.hashes.get(key_id) {
			Some(list) => list,
			None => return false,
		};
		for hash in hash_list {
			if Yescrypt::default()
				.verify_password(secret.as_bytes(), hash.as_str())
				.is_ok()
			{
				return true;
			}
		}
		false
	}
}

/// Tracks per-IP auth failures and blocks IPs exceeding the threshold.
///
/// Uses a fixed window: the timer starts on the first failure.
/// 10 failures must occur within `window` of that first failure to trigger a block.
/// If the window expires, the counter resets - not a rolling window.
struct FailureTracker {
	fails: Mutex<HashMap<IpAddr, (u32, Instant)>>,
	max_fails: u32,
	window: Duration,
}

impl FailureTracker {
	fn new(max_fails: u32, window: Duration) -> Self {
		Self {
			fails: Mutex::new(HashMap::new()),
			max_fails,
			window,
		}
	}

	fn record(&self, addr: IpAddr, success: bool) {
		let mut map = self.fails.lock().unwrap();
		if success {
			map.remove(&addr);
			return;
		}
		let entry = map.entry(addr).or_insert((0, Instant::now()));
		let (count, since) = *entry;
		if since.elapsed() > self.window {
			*entry = (1, Instant::now());
			return;
		}
		entry.0 = count + 1;
	}

	fn is_blocked(&self, addr: IpAddr) -> bool {
		let map = self.fails.lock().unwrap();
		match map.get(&addr) {
			Some((count, since)) => since.elapsed() <= self.window && *count >= self.max_fails,
			None => false,
		}
	}

	fn refresh_block(&self, addr: IpAddr) {
		let mut map = self.fails.lock().unwrap();
		if let Some((count, since)) = map.get_mut(&addr) {
			if *count >= self.max_fails && since.elapsed() <= self.window {
				*since = Instant::now();
			}
		}
	}

	fn prune(&self) {
		let mut map = self.fails.lock().unwrap();
		map.retain(|_, (_, since)| since.elapsed() <= self.window);
	}
}

struct AppState {
	config: Config,
	keys: HashMap<String, Keys>,
	semaphores: HashMap<String, Arc<Semaphore>>,
	auth_semaphore: Arc<Semaphore>,
	failure_tracker: Arc<FailureTracker>,
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

	let auth_semaphore = Arc::new(Semaphore::new(4));
	let failure_tracker = Arc::new(FailureTracker::new(10, Duration::from_secs(600)));

	let state = Arc::new(AppState {
		config: config.clone(),
		keys,
		semaphores,
		auth_semaphore,
		failure_tracker,
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

	let failure_tracker = state.failure_tracker.clone();
	let router = router.with_state(state);

	let addr_str = format!("{}:{}", cli.address, cli.port);
	let addr: SocketAddr = addr_str.parse().expect("Invalid address or port");

	info!("[+] listening on {}", addr);
	let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

	let router = if !config.global.trusted_proxies.is_empty() {
		rate_limited(
			router,
			tower_governor::key_extractor::SmartIpKeyExtractor,
			failure_tracker,
		)
	} else {
		rate_limited(
			router,
			tower_governor::key_extractor::PeerIpKeyExtractor,
			failure_tracker,
		)
	};

	axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
		.await
		.unwrap();
}

/// Wraps the router with a governor rate-limiting layer using the given key extractor
/// and spawns a background task to clean up rate limiter and failure tracker storage.
fn rate_limited<K>(router: Router, key_extractor: K, failure_tracker: Arc<FailureTracker>) -> Router
where
	K: tower_governor::key_extractor::KeyExtractor + Send + Sync + 'static,
	K::Key: Send + Sync + 'static,
{
	let governor_conf = Arc::new(
		tower_governor::governor::GovernorConfigBuilder::default()
			.per_second(2)
			.burst_size(5)
			.key_extractor(key_extractor)
			.finish()
			.unwrap(),
	);
	let limiter = governor_conf.limiter().clone();
	tokio::spawn(async move {
		let interval = Duration::from_secs(60);
		loop {
			tokio::time::sleep(interval).await;
			limiter.retain_recent();
			failure_tracker.prune();
		}
	});
	router.layer(GovernorLayer::new(governor_conf))
}

async fn handle_route(
	route_name: String,
	headers: HeaderMap,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	State(state): State<Arc<AppState>>,
	semaphore: Arc<Semaphore>,
) -> Result<Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>>, (StatusCode, String)> {
	let client_ip = resolve_client_ip(addr, &headers, &state.config.global.trusted_proxies);

	info!("[+] request: {}: client_ip: {}", route_name, client_ip);

	let route_config = state
		.config
		.routes
		.get(&route_name)
		.ok_or((StatusCode::NOT_FOUND, format!("Route {} not found", route_name)))?;

	let auth_header_name = &state.config.global.auth_header;
	let auth_key = headers
		.get(auth_header_name)
		.and_then(|h| h.to_str().ok())
		.ok_or((StatusCode::UNAUTHORIZED, "Missing auth header".to_string()))?;

	// check failure tracker before any auth work
	if state.failure_tracker.is_blocked(client_ip) {
		state.failure_tracker.refresh_block(client_ip);
		warn!("[!] blocked: {} exceeded failure threshold", client_ip);
		tokio::time::sleep(Duration::from_millis(500)).await;
		return Err((StatusCode::TOO_MANY_REQUESTS, "Too many failed attempts".to_string()));
	}

	let route_keys = state.keys.get(&route_name).ok_or((
		StatusCode::INTERNAL_SERVER_ERROR,
		"Keys not loaded for route".to_string(),
	))?;

	// acquire global auth semaphore to cap in-flight yescrypt work
	let auth_permit = match state.auth_semaphore.clone().try_acquire_owned() {
		Ok(p) => p,
		Err(_) => {
			warn!("[!] auth concurrency limit reached");
			tokio::time::sleep(Duration::from_millis(500)).await;
			return Err((
				StatusCode::SERVICE_UNAVAILABLE,
				"Auth concurrency limit reached".to_string(),
			));
		}
	};

	// run yescrypt in a blocking thread
	let key_clone = auth_key.to_string();
	let keys_for_verify = route_keys.clone();
	let verified = tokio::task::spawn_blocking(move || keys_for_verify.verify(&key_clone))
		.await
		.unwrap_or_else(|e| {
			error!("[!] spawn_blocking panic during auth: {}", e);
			false
		});

	drop(auth_permit);

	if !verified {
		state.failure_tracker.record(client_ip, false);
		warn!("[!] auth failed: {} from {}", route_name, client_ip);
		// Step 4: Tarpit on auth failure
		tokio::time::sleep(Duration::from_millis(500)).await;
		return Err((StatusCode::UNAUTHORIZED, "Invalid auth key".to_string()));
	}

	state.failure_tracker.record(client_ip, true);

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
			(StatusCode::INTERNAL_SERVER_ERROR, "Failed to execute shell".to_string())
		})?;

	info!("[+] spawn: {}: client_ip: {}", route_name, client_ip);
	let stdout = child.stdout.take().unwrap();
	let stderr = child.stderr.take().unwrap();

	let timeout_duration = Duration::from_secs(state.config.global.timeout);

	tokio::spawn(async move {
		match tokio::time::timeout(timeout_duration, child.wait()).await {
			Ok(Ok(status)) => {
				info!("[+] exit: {}: return: {:?}", route_name, status.code().unwrap_or(-1));
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

	fn line_event_stream<R: tokio::io::AsyncBufRead + Unpin>(
		reader: tokio::io::Lines<R>,
		r#type: &'static str,
	) -> impl Stream<Item = Result<Event, std::convert::Infallible>> {
		stream::unfold(reader, move |mut reader| async move {
			match reader.next_line().await {
				Ok(Some(line)) => Some((
					Ok(Event::default()
						.json_data(OutputLine {
							r#type: r#type.to_string(),
							line,
						})
						.unwrap()),
					reader,
				)),
				_ => None,
			}
		})
	}

	let stdout_stream = line_event_stream(stdout_reader, "stdout");
	let stderr_stream = line_event_stream(stderr_reader, "stderr");
	let combined_stream = stream::select(stdout_stream, stderr_stream);
	Ok(Sse::new(combined_stream).keep_alive(KeepAlive::default()))
}

#[cfg(test)]
mod tests {
	use super::*;
	use yescrypt::PasswordHasher;

	#[test]
	fn test_keys_verify_valid() {
		let yescrypt = Yescrypt::default();
		let hash_obj = yescrypt.hash_password(b"super53cr37").expect("hashing failed");
		let hash_str = hash_obj.to_string();
		let key_id = "testkey1";
		let keys = Keys {
			hashes: {
				let mut m = HashMap::new();
				m.insert(key_id.to_string(), vec![hash_str.clone()]);
				m
			},
		};
		assert!(yescrypt.verify_password(b"super53cr37", hash_str.as_str()).is_ok());
		assert!(keys.verify(&format!("{}.{}", key_id, "super53cr37")));
	}

	#[test]
	fn test_keys_verify_wrong_secret() {
		let yescrypt = Yescrypt::default();
		let hash = yescrypt.hash_password(b"correct").expect("hashing failed").to_string();
		let key_id = "testkey2";
		let keys = Keys {
			hashes: {
				let mut m = HashMap::new();
				m.insert(key_id.to_string(), vec![hash]);
				m
			},
		};
		assert!(!keys.verify(&format!("{}.{}", key_id, "wrong")));
	}

	#[test]
	fn test_keys_verify_unknown_id() {
		let keys = Keys {
			hashes: {
				let mut m = HashMap::new();
				m.insert("otherid".to_string(), vec!["$y$j9T$hash".to_string()]);
				m
			},
		};
		assert!(!keys.verify("unknownid.secret"));
	}

	#[test]
	fn test_keys_verify_no_dot() {
		let keys = Keys {
			hashes: {
				let mut m = HashMap::new();
				m.insert("id".to_string(), vec!["$y$j9T$hash".to_string()]);
				m
			},
		};
		assert!(!keys.verify("noseparator"));
	}

	#[test]
	fn test_keys_from_file_rejects_malformed() {
		let dir = std::env::temp_dir();
		let path = dir.join("cause_test_malformed_keys");
		fs::write(
			&path,
			"$y$j9T$xlKmMsoZxul/zvPXLC/Aj.$m0BFqZYiyDAF7bh/Tb3.CDTH5kgmBfBRhXbKAO0nco7\n",
		)
		.unwrap();
		let result = Keys::from_file(path.to_str().unwrap());
		assert!(result.is_err());
		fs::remove_file(&path).ok();
	}

	#[test]
	fn test_keys_from_file_accepts_keyid_format() {
		let dir = std::env::temp_dir();
		let path = dir.join("cause_test_keyid_keys");
		fs::write(
			&path,
			"a1b2c3d4:$y$j9T$xlKmMsoZxul/zvPXLC/Aj.$m0BFqZYiyDAF7bh/Tb3.CDTH5kgmBfBRhXbKAO0nco7\n",
		)
		.unwrap();
		let result = Keys::from_file(path.to_str().unwrap());
		assert!(result.is_ok());
		fs::remove_file(&path).ok();
	}

	#[test]
	fn test_failure_tracker_blocks_after_threshold() {
		let tracker = FailureTracker::new(3, Duration::from_secs(60));
		let addr = "127.0.0.1".parse::<IpAddr>().unwrap();
		tracker.record(addr, false);
		tracker.record(addr, false);
		tracker.record(addr, false);
		assert!(tracker.is_blocked(addr));
	}

	#[test]
	fn test_failure_tracker_clears_on_success() {
		let tracker = FailureTracker::new(3, Duration::from_secs(60));
		let addr = "127.0.0.1".parse::<IpAddr>().unwrap();
		tracker.record(addr, false);
		tracker.record(addr, false);
		tracker.record(addr, true);
		assert!(!tracker.is_blocked(addr));
	}

	#[test]
	fn test_failure_tracker_success_only_clears_own_ip() {
		let tracker = FailureTracker::new(3, Duration::from_secs(60));
		let addr_a = "10.0.0.1".parse::<IpAddr>().unwrap();
		let addr_b = "10.0.0.2".parse::<IpAddr>().unwrap();
		tracker.record(addr_a, false);
		tracker.record(addr_a, false);
		tracker.record(addr_a, false);
		assert!(tracker.is_blocked(addr_a));
		tracker.record(addr_b, true);
		assert!(tracker.is_blocked(addr_a));
	}

	#[test]
	fn test_failure_tracker_prune_removes_stale() {
		let tracker = FailureTracker::new(3, Duration::from_millis(50));
		let addr = "127.0.0.1".parse::<IpAddr>().unwrap();
		tracker.record(addr, false);
		tracker.record(addr, false);
		tracker.record(addr, false);
		assert!(tracker.is_blocked(addr));
		std::thread::sleep(Duration::from_millis(100));
		tracker.prune();
		assert!(!tracker.is_blocked(addr));
	}

	#[test]
	fn test_failure_tracker_prune_keeps_fresh() {
		let tracker = FailureTracker::new(3, Duration::from_secs(60));
		let addr = "127.0.0.1".parse::<IpAddr>().unwrap();
		tracker.record(addr, false);
		tracker.record(addr, false);
		tracker.record(addr, false);
		assert!(tracker.is_blocked(addr));
		tracker.prune();
		assert!(tracker.is_blocked(addr));
	}

	#[test]
	fn test_failure_tracker_refresh_extends_block() {
		let tracker = FailureTracker::new(3, Duration::from_millis(200));
		let addr = "127.0.0.1".parse::<IpAddr>().unwrap();
		tracker.record(addr, false);
		tracker.record(addr, false);
		tracker.record(addr, false);
		assert!(tracker.is_blocked(addr));
		std::thread::sleep(Duration::from_millis(150));
		assert!(tracker.is_blocked(addr));
		tracker.refresh_block(addr);
		assert!(tracker.is_blocked(addr));
		std::thread::sleep(Duration::from_millis(50));
		assert!(tracker.is_blocked(addr));
		std::thread::sleep(Duration::from_millis(160));
		assert!(!tracker.is_blocked(addr));
	}
}
