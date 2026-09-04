use crate::auth::{FailureTracker, Keys};
use crate::config::Config;
use crate::executor;
use crate::net::{normalize_ip, resolve_client_ip};
use crate::route_state::RouteState;
use anyhow::Context;
use axum::{
	extract::{ConnectInfo, Path, State},
	http::{HeaderMap, StatusCode},
	response::{
		Sse,
		sse::{Event, KeepAlive},
	},
};
use futures_util::stream::Stream;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{error, info, info_span, warn};

pub struct AppState {
	pub(crate) config: Config,
	pub(crate) routes: HashMap<String, Arc<RouteState>>,
	pub(crate) auth_semaphore: Arc<Semaphore>,
	/// Single permit reserved for IPs with a clean recent failure history, so known-good
	/// clients make progress even when attackers saturate the general semaphore queue.
	pub(crate) auth_reserved_semaphore: Arc<Semaphore>,
	pub(crate) failure_tracker: Arc<FailureTracker>,
	/// Per-IP count of in-flight auth attempts; caps how many queue slots one source can hold.
	pub(crate) inflight_auth: Mutex<HashMap<IpAddr, u32>>,
	/// Number of tasks currently waiting on the general auth semaphore; bounds queue depth.
	pub(crate) auth_waiters: AtomicUsize,
}

impl AppState {
	pub async fn from_config(config: Config) -> anyhow::Result<Self> {
		let mut routes = HashMap::new();
		for (name, route) in &config.routes {
			let keys = Keys::from_file(&route.keys).with_context(|| format!("route {}", name))?;
			info!(route = %name, "keys loaded");
			let semaphore = Arc::new(Semaphore::new(route.concurrency.get()));
			routes.insert(
				name.clone(),
				Arc::new(RouteState {
					config: route.clone(),
					keys: Arc::new(keys),
					semaphore,
				}),
			);
		}
		let global = config.global.clone();
		// carve one permit out for clean-history clients when the pool is big enough
		let reserved = if global.auth_semaphore_size.get() >= 2 { 1 } else { 0 };
		Ok(Self {
			config,
			routes,
			auth_semaphore: Arc::new(Semaphore::new(global.auth_semaphore_size.get() - reserved)),
			auth_reserved_semaphore: Arc::new(Semaphore::new(reserved)),
			inflight_auth: Mutex::new(HashMap::new()),
			auth_waiters: AtomicUsize::new(0),
			failure_tracker: Arc::new(FailureTracker::new(
				global.failure_threshold.get(),
				Duration::from_secs(global.failure_window_secs.get()),
				Duration::from_secs(global.block_duration_secs.get()),
				global.failure_max_entries,
			)),
		})
	}
}

/// Decrements the per-IP in-flight auth counter on drop, so early returns and panics
/// cannot leak counts.
pub(crate) struct InflightGuard {
	state: Arc<AppState>,
	ip: IpAddr,
}

impl Drop for InflightGuard {
	fn drop(&mut self) {
		let mut map = self.state.inflight_auth.lock().unwrap();
		if let Some(count) = map.get_mut(&self.ip) {
			*count -= 1;
			if *count == 0 {
				map.remove(&self.ip);
			}
		}
	}
}

/// Registers an in-flight auth attempt for the IP, or returns None if the IP already
/// holds too many concurrent attempts.
pub(crate) fn register_inflight(state: &Arc<AppState>, ip: IpAddr) -> Option<InflightGuard> {
	let max = state.config.global.max_inflight_auth_per_ip.get();
	let mut map = state.inflight_auth.lock().unwrap();
	let count = map.entry(ip).or_insert(0);
	if *count >= max {
		return None;
	}
	*count += 1;
	drop(map);
	Some(InflightGuard {
		state: state.clone(),
		ip,
	})
}

/// Decrements the auth waiter counter on drop.
struct WaiterGuard<'a>(&'a AtomicUsize);

impl Drop for WaiterGuard<'_> {
	fn drop(&mut self) {
		self.0.fetch_sub(1, Ordering::AcqRel);
	}
}

/// Queues fairly (FIFO) for an auth permit with a bounded wait.
/// Clean-history clients may grab the reserved permit and bypass the general queue.
/// Returns None on queue overflow, acquire timeout, or semaphore closure.
pub(crate) async fn acquire_auth_permit(state: &Arc<AppState>, clean: bool) -> Option<OwnedSemaphorePermit> {
	if clean && let Ok(p) = state.auth_reserved_semaphore.clone().try_acquire_owned() {
		return Some(p);
	}
	// bound the wait queue: fast-fail instead of piling up waiters under a flood
	let waiters = state.auth_waiters.fetch_add(1, Ordering::AcqRel);
	let _waiter_guard = WaiterGuard(&state.auth_waiters);
	if waiters >= state.config.global.max_auth_queue_depth.get() {
		return None;
	}
	match tokio::time::timeout(
		Duration::from_millis(state.config.global.auth_acquire_timeout_ms),
		state.auth_semaphore.clone().acquire_owned(),
	)
	.await
	{
		Ok(Ok(p)) => Some(p),
		// semaphore closed (shutdown) or acquire timed out
		Ok(Err(_)) | Err(_) => None,
	}
}

/// Sleeps for the configured tarpit duration.
async fn tarpit(state: &Arc<AppState>) {
	tokio::time::sleep(Duration::from_millis(state.config.global.tarpit_duration_ms)).await;
}

/// Runs a dummy yescrypt verification so that failure paths that never reach real key verification
/// cost the same as a wrong-key failure.
async fn dummy_auth_work(state: &Arc<AppState>) {
	let permit = match acquire_auth_permit(state, false).await {
		Some(p) => p,
		// timing matches the real path, which returns after the same acquire timeout
		None => return,
	};
	if let Err(e) = tokio::task::spawn_blocking(crate::auth::dummy_verify).await {
		error!(phase = "dummy_auth", error = %e, "spawn_blocking panicked");
	}
	drop(permit);
}

/// Records an auth failure.
async fn auth_failure(
	state: &Arc<AppState>,
	canonical_ip: std::net::IpAddr,
	route: &str,
	reason: &str,
	dummy_work: bool,
) -> (StatusCode, String) {
	state.failure_tracker.record(canonical_ip, false);
	warn!(client_ip = %canonical_ip, route = %route, reason = %reason, "auth failed");
	if dummy_work {
		dummy_auth_work(state).await;
	}
	tarpit(state).await;
	(StatusCode::UNAUTHORIZED, "Unauthorized".to_string())
}

/// Checks if an IP is blocked by the failure tracker.
async fn check_blocked(state: &Arc<AppState>, canonical_ip: std::net::IpAddr) -> Result<(), (StatusCode, String)> {
	if !state.failure_tracker.is_blocked(canonical_ip) {
		return Ok(());
	}
	state.failure_tracker.refresh_block(canonical_ip);
	warn!(client_ip = %canonical_ip, "ip blocked: failure threshold exceeded");
	tarpit(state).await;
	Err((StatusCode::TOO_MANY_REQUESTS, "Too many failed attempts".to_string()))
}

/// Looks up a route by name, or returns a failure response for unknown routes.
fn lookup_route(state: &Arc<AppState>, route_name: &str) -> Result<Arc<RouteState>, (StatusCode, String)> {
	state
		.routes
		.get(route_name)
		.cloned()
		.ok_or_else(|| (StatusCode::NOT_FOUND, "Unknown route".to_string()))
}

/// Extracts the auth key from the request headers.
fn extract_auth_key(state: &Arc<AppState>, headers: &HeaderMap) -> Result<String, String> {
	let auth_header_name = &state.config.global.auth_header;
	headers
		.get(auth_header_name)
		.and_then(|h| h.to_str().ok())
		.map(|s| s.to_string())
		.ok_or_else(|| "missing header".to_string())
}

/// Acquires an in-flight auth permit for the IP, or returns a rate-limit error.
async fn check_inflight(state: &Arc<AppState>, canonical_ip: std::net::IpAddr) -> Result<(), (StatusCode, String)> {
	if register_inflight(state, canonical_ip).is_some() {
		return Ok(());
	}
	warn!(client_ip = %canonical_ip, "auth concurrency limit per ip");
	tarpit(state).await;
	Err((
		StatusCode::TOO_MANY_REQUESTS,
		"Too many concurrent requests".to_string(),
	))
}

/// Acquires an auth semaphore permit with fair queuing.
async fn acquire_permit(
	state: &Arc<AppState>,
	canonical_ip: std::net::IpAddr,
) -> Result<OwnedSemaphorePermit, (StatusCode, String)> {
	let clean = !state.failure_tracker.has_recent_failures(canonical_ip);
	match acquire_auth_permit(state, clean).await {
		Some(p) => Ok(p),
		None => {
			warn!("auth concurrency limit: acquire timed out or queue full");
			Err((StatusCode::SERVICE_UNAVAILABLE, "Server busy".to_string()))
		}
	}
}

/// Verifies an auth key against the route keys using a blocking task.
async fn verify_key(route_state: &Arc<RouteState>, key: String) -> bool {
	let keys_for_verify = Arc::clone(&route_state.keys);
	tokio::task::spawn_blocking(move || keys_for_verify.verify(&key))
		.await
		.unwrap_or_else(|e| {
			error!(phase = "auth", error = %e, "spawn_blocking panicked");
			false
		})
}

/// Authenticates the request: checks failure tracker, validates route existence,
/// validates auth header, verifies the key, and records success or failure.
async fn authenticate(
	route_name: &str,
	headers: &HeaderMap,
	canonical_ip: std::net::IpAddr,
	state: &Arc<AppState>,
) -> Result<Arc<RouteState>, (StatusCode, String)> {
	check_blocked(state, canonical_ip).await?;

	let route_state = lookup_route(state, route_name)?;
	let auth_key = match extract_auth_key(state, headers) {
		Ok(key) => key,
		Err(reason) => {
			return Err(auth_failure(state, canonical_ip, route_name, &reason, true).await);
		}
	};

	check_inflight(state, canonical_ip).await?;
	let auth_permit = acquire_permit(state, canonical_ip).await?;
	let verified = verify_key(&route_state, auth_key).await;
	drop(auth_permit);

	if !verified {
		return Err(auth_failure(state, canonical_ip, route_name, "invalid key", false).await);
	}

	state.failure_tracker.record(canonical_ip, true);
	Ok(route_state)
}

/// health check endpoint
pub async fn health() -> StatusCode {
	StatusCode::OK
}

pub async fn handle_route(
	Path(route_name): Path<String>,
	headers: HeaderMap,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	State(state): State<Arc<AppState>>,
) -> Result<Sse<impl Stream<Item = Result<Event, String>>>, (StatusCode, String)> {
	let raw_ip = resolve_client_ip(addr.ip(), &headers, &state.config.global.trusted_proxies);
	let canonical_ip = normalize_ip(raw_ip);
	let request_id = uuid::Uuid::new_v4().to_string();
	let span = info_span!("request", route = %route_name, client_ip = %canonical_ip, request_id = %request_id);
	let _enter = span.enter();
	info!("request accepted");
	let route_state = authenticate(&route_name, &headers, canonical_ip, &state).await?;
	let limits = executor::ExecutionLimits {
		timeout_duration: Duration::from_secs(state.config.global.timeout.get()),
		grace_duration: Duration::from_secs(state.config.global.kill_grace_secs.get()),
		drain_duration: Duration::from_secs(state.config.global.drain_grace_secs.get()),
		max_line_length: state.config.global.max_line_length.get(),
	};
	let execution = executor::RouteExecution::spawn(&route_name, &route_state, limits).await?;
	Ok(Sse::new(execution.stream_output()).keep_alive(KeepAlive::default()))
}
