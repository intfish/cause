use axum::http::HeaderMap;
use serde::Serialize;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use std::sync::Mutex;
use yescrypt::password_hash::PasswordVerifier;
use yescrypt::Yescrypt;

/// Resolves the effective client IP from the TCP peer address and proxy headers.
/// X-Forwarded-For => X-Real-IP => TCP peer address
pub fn resolve_client_ip(addr: SocketAddr, headers: &HeaderMap, trusted_proxies: &[IpAddr]) -> IpAddr {
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

#[derive(Serialize, Debug)]
pub struct OutputLine {
	pub r#type: String,
	pub line: String,
}

#[derive(Clone)]
pub struct Keys {
	// key_id -> list of yescrypt hashes (tolerates ID collisions)
	pub(crate) hashes: HashMap<String, Vec<String>>,
}

impl Keys {
	pub fn from_file(path: &str) -> Result<Self, String> {
		let content = std::fs::read_to_string(path).map_err(|e| format!("failed to read keys file {}: {}", path, e))?;
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

	pub fn verify(&self, key: &str) -> bool {
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
pub struct FailureTracker {
	fails: Mutex<HashMap<IpAddr, (u32, Instant)>>,
	max_fails: u32,
	window: Duration,
}

impl FailureTracker {
	pub fn new(max_fails: u32, window: Duration) -> Self {
		Self {
			fails: Mutex::new(HashMap::new()),
			max_fails,
			window,
		}
	}

	pub fn record(&self, addr: IpAddr, success: bool) {
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

	pub fn is_blocked(&self, addr: IpAddr) -> bool {
		let map = self.fails.lock().unwrap();
		match map.get(&addr) {
			Some((count, since)) => since.elapsed() <= self.window && *count >= self.max_fails,
			None => false,
		}
	}

	pub fn refresh_block(&self, addr: IpAddr) {
		let mut map = self.fails.lock().unwrap();
		if let Some((count, since)) = map.get_mut(&addr)
			&& *count >= self.max_fails && since.elapsed() <= self.window {
			*since = Instant::now();
		}
	}

	pub fn prune(&self) {
		let mut map = self.fails.lock().unwrap();
		map.retain(|_, (_, since)| since.elapsed() <= self.window);
	}
}
