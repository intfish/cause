use crate::auth::{FailureTracker, Keys, OutputLine, resolve_client_ip};
use crate::config::Config;
use axum::{
	Router,
	extract::{self as ax_extract, Path, State},
	http::{HeaderMap, StatusCode},
	response::{
		Sse,
		sse::{Event, KeepAlive},
	},
};
use futures_util::stream::{self, Stream};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

pub struct AppState {
	pub(crate) config: Config,
	pub(crate) keys: HashMap<String, Keys>,
	pub(crate) semaphores: HashMap<String, Arc<Semaphore>>,
	pub(crate) auth_semaphore: Arc<Semaphore>,
	pub(crate) failure_tracker: Arc<FailureTracker>,
}

impl AppState {
	pub fn new(
		config: Config,
		keys: HashMap<String, Keys>,
		semaphores: HashMap<String, Arc<Semaphore>>,
		auth_semaphore: Arc<Semaphore>,
		failure_tracker: Arc<FailureTracker>,
	) -> Self {
		Self {
			config,
			keys,
			semaphores,
			auth_semaphore,
			failure_tracker,
		}
	}
}

/// Wraps the router with a governor rate-limiting layer using the given key extractor
/// and spawns a background task to clean up rate limiter and failure tracker storage.
pub fn rate_limited<K>(router: Router, key_extractor: K, failure_tracker: Arc<FailureTracker>) -> Router
where
	K: tower_governor::key_extractor::KeyExtractor + Send + Sync + 'static,
	K::Key: Send + Sync + 'static,
{
	let governor_conf = Arc::new(
		match tower_governor::governor::GovernorConfigBuilder::default()
			.per_second(2)
			.burst_size(5)
			.key_extractor(key_extractor)
			.finish()
		{
			Some(c) => c,
			None => {
				tracing::error!("[!] failed to build governor config");
				std::process::exit(1);
			}
		},
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
	router.layer(tower_governor::GovernorLayer::new(governor_conf))
}

pub async fn handle_route(
	Path(route_name): Path<String>,
	headers: HeaderMap,
	ax_extract::ConnectInfo(addr): ax_extract::ConnectInfo<SocketAddr>,
	State(state): State<Arc<AppState>>,
) -> Result<Sse<impl Stream<Item = Result<Event, String>>>, (StatusCode, String)> {
	let client_ip = resolve_client_ip(addr, &headers, &state.config.global.trusted_proxies);

	info!("[+] request: {}: client_ip: {}", route_name, client_ip);

	let route_config = match state.config.routes.get(&route_name) {
		Some(cfg) => cfg,
		None => return Err((StatusCode::NOT_FOUND, "Route not found".to_string())),
	};

	let semaphore = match state.semaphores.get(&route_name) {
		Some(sem) => sem.clone(),
		None => return Err((StatusCode::NOT_FOUND, "Route not found".to_string())),
	};

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
		.process_group(0)
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
				error!("[!] timeout, killing process group for: {}", route_name);
				let _ = nix::sys::signal::killpg(Pid::from_raw(0), nix::sys::signal::Signal::SIGTERM);
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
	) -> impl Stream<Item = Result<Event, String>> {
		stream::unfold(reader, move |mut reader| async move {
			match reader.next_line().await {
				Ok(Some(line)) => Some((
					Event::default()
						.json_data(OutputLine {
							r#type: r#type.to_string(),
							line,
						})
						.map_err(|e| format!("json error: {}", e)),
					reader,
				)),
				Err(e) => {
					warn!("[!] read error on {}: {}", r#type, e);
					None
				}
				Ok(None) => None,
			}
		})
	}

	let stdout_stream = line_event_stream(stdout_reader, "stdout");
	let stderr_stream = line_event_stream(stderr_reader, "stderr");
	let combined_stream = stream::select(stdout_stream, stderr_stream);
	Ok(Sse::new(combined_stream).keep_alive(KeepAlive::default()))
}
