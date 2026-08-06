use crate::net::normalize_ip;
use lru::LruCache;
use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use yescrypt::Yescrypt;
use yescrypt::password_hash::{PasswordHasher, PasswordVerifier};

static DUMMY_HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn get_dummy_hash() -> &'static str {
	DUMMY_HASH.get_or_init(|| {
		Yescrypt::default()
			.hash_password(b"this might be overkill")
			.expect("yescrypt hashing of constant")
			.to_string()
	})
}

pub fn dummy_verify() {
	let _ = Yescrypt::default()
		.verify_password(b"it probably is", get_dummy_hash())
		.is_ok();
}

#[derive(Clone, Debug)]
pub struct Keys {
	// key_id -> list of yescrypt hashes (tolerates ID collisions)
	pub(crate) hashes: HashMap<String, Vec<String>>,
}

#[derive(thiserror::Error, Debug)]
pub enum KeysError {
	#[error("failed to read keys file {}: {source}", .path.display())]
	Read {
		path: PathBuf,
		#[source]
		source: std::io::Error,
	},
	#[error("malformed line in {} (no ':'): {line}", .path.display())]
	MalformedLine { path: PathBuf, line: String },
	#[error("invalid hash in {} line {}: {reason}", .path.display(), .line_num)]
	InvalidHash {
		path: PathBuf,
		line: String,
		line_num: usize,
		reason: String,
	},
}

impl Keys {
	pub fn from_file(path: &Path) -> Result<Self, KeysError> {
		let content = std::fs::read_to_string(path).map_err(|e| KeysError::Read {
			path: path.to_path_buf(),
			source: e,
		})?;
		let mut hashes: HashMap<String, Vec<String>> = HashMap::new();
		for (line_num, line) in content.lines().enumerate() {
			let line = line.trim();
			if line.is_empty() {
				continue;
			}
			// require keyid:hash format
			let (key_id, hash) = line.split_once(':').ok_or_else(|| KeysError::MalformedLine {
				path: path.to_path_buf(),
				line: line.to_string(),
			})?;
			let key_id = key_id.to_string();
			let hash = hash.to_string();
			let hash_fields: Vec<&str> = hash.split('$').collect();
			if hash_fields.len() < 3 || !hash_fields[0].is_empty() || hash_fields[1] != "y" {
				return Err(KeysError::InvalidHash {
					path: path.to_path_buf(),
					line: line.to_string(),
					line_num: line_num + 1,
					reason: "not a valid yescrypt PHC string".into(),
				});
			}
			hashes.entry(key_id).or_default().push(hash);
		}
		Ok(Self { hashes })
	}

	pub fn verify(&self, key: &str) -> bool {
		let (key_id, secret) = match key.split_once('.') {
			Some((id, secret)) => (id, secret),
			None => {
				dummy_verify();
				return false;
			}
		};
		let hash_list = match self.hashes.get(key_id) {
			Some(list) => list,
			None => {
				dummy_verify();
				return false;
			}
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
/// Keys are normalized via `normalize_ip`.
///
/// Uses a fixed window: the timer starts on the first failure.
/// `max_fails` must occur within `window` of that first failure to trigger a block.
/// If the window expires, the counter resets - not a rolling window.
///
/// Blocked IPs are stored separately and never evicted by capacity.
/// Non-blocked entries use LRU eviction ordered by most-recent-failure time.
/// This is a slightly stronger eviction policy than "oldest since first":
/// an entry with many historical failures but no recent ones may survive longer
/// than one with a single recent failure, but both are bounded by capacity.
struct Inner {
	fails: LruCache<IpAddr, (u32, Instant)>,
	blocked: HashMap<IpAddr, Instant>,
}

pub struct FailureTracker {
	inner: Mutex<Inner>,
	max_fails: u32,
	window: Duration,
	block_duration: Duration,
}

impl FailureTracker {
	pub fn new(max_fails: u32, window: Duration, block_duration: Duration, max_entries: NonZeroUsize) -> Self {
		Self {
			inner: Mutex::new(Inner {
				fails: LruCache::new(max_entries),
				blocked: HashMap::new(),
			}),
			max_fails,
			window,
			block_duration,
		}
	}

	pub fn record(&self, addr: IpAddr, success: bool) {
		let addr = normalize_ip(addr);
		let now = Instant::now();
		let mut inner = self.inner.lock().unwrap();

		// lazily expire a stale block for this addr
		if let Some(since) = inner.blocked.get(&addr) {
			if since.elapsed() > self.block_duration {
				inner.blocked.remove(&addr);
			}
			return;
		}

		if success {
			inner.fails.pop(&addr);
			return;
		}

		let (count, since) = match inner.fails.pop(&addr) {
			Some((c, s)) if s.elapsed() <= self.window => (c.saturating_add(1), s),
			_ => (1, now),
		};

		if count >= self.max_fails {
			inner.blocked.insert(addr, now);
		} else {
			inner.fails.push(addr, (count, since));
		}
	}

	pub fn is_blocked(&self, addr: IpAddr) -> bool {
		let addr = normalize_ip(addr);
		let inner = self.inner.lock().unwrap();
		matches!(inner.blocked.get(&addr), Some(since) if since.elapsed() <= self.block_duration)
	}

	/// Returns true if the IP has any failure recorded within the current window.
	pub fn has_recent_failures(&self, addr: IpAddr) -> bool {
		let addr = normalize_ip(addr);
		let inner = self.inner.lock().unwrap();
		if matches!(inner.blocked.get(&addr), Some(since) if since.elapsed() <= self.block_duration) {
			return true;
		}
		match inner.fails.peek(&addr) {
			Some((_count, since)) => since.elapsed() <= self.window,
			None => false,
		}
	}

	pub fn refresh_block(&self, addr: IpAddr) {
		let addr = normalize_ip(addr);
		let mut inner = self.inner.lock().unwrap();
		if let Some(since) = inner.blocked.get_mut(&addr) {
			if since.elapsed() <= self.block_duration {
				*since = Instant::now();
			} else {
				inner.blocked.remove(&addr);
			}
		}
	}

	pub fn prune(&self) {
		let mut inner = self.inner.lock().unwrap();
		inner.blocked.retain(|_, s| s.elapsed() <= self.block_duration);
		let expired: Vec<IpAddr> = inner
			.fails
			.iter()
			.filter(|(_, (_, since))| since.elapsed() > self.window)
			.map(|(k, _)| *k)
			.collect();
		for k in expired {
			inner.fails.pop(&k);
		}
	}
}
