use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tracing::warn;

fn default_concurrency() -> NonZeroUsize {
	NonZeroUsize::new(1).unwrap()
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
pub struct GlobalConfig {
	pub auth_header: String,
	pub timeout: NonZeroU64,
	pub trusted_proxies: Vec<IpAddr>,
	pub auth_semaphore_size: NonZeroUsize,
	pub failure_threshold: NonZeroU32,
	pub failure_window_secs: NonZeroU64,
	pub block_duration_secs: NonZeroU64,
	pub tarpit_duration_ms: u64,
	pub rate_limit_per_second: NonZeroU64,
	pub rate_limit_burst: NonZeroU32,
	pub kill_grace_secs: NonZeroU64,
	pub drain_grace_secs: NonZeroU64,
	pub max_line_length: NonZeroUsize,
	pub failure_max_entries: NonZeroUsize,
	pub auth_acquire_timeout_ms: u64,
	pub max_inflight_auth_per_ip: NonZeroU32,
	pub max_auth_queue_depth: NonZeroUsize,
}

impl Default for GlobalConfig {
	fn default() -> Self {
		Self {
			auth_header: "x-api-key".to_string(),
			timeout: NonZeroU64::new(900).unwrap(),
			trusted_proxies: Vec::new(),
			auth_semaphore_size: NonZeroUsize::new(4).unwrap(),
			failure_threshold: NonZeroU32::new(10).unwrap(),
			failure_window_secs: NonZeroU64::new(600).unwrap(),
			block_duration_secs: NonZeroU64::new(600).unwrap(),
			tarpit_duration_ms: 500,
			rate_limit_per_second: NonZeroU64::new(2).unwrap(),
			rate_limit_burst: NonZeroU32::new(5).unwrap(),
			kill_grace_secs: NonZeroU64::new(1).unwrap(),
			drain_grace_secs: NonZeroU64::new(2).unwrap(),
			max_line_length: NonZeroUsize::new(64 * 1024).unwrap(),
			failure_max_entries: NonZeroUsize::new(100_000).unwrap(),
			auth_acquire_timeout_ms: 2000,
			max_inflight_auth_per_ip: NonZeroU32::new(2).unwrap(),
			max_auth_queue_depth: NonZeroUsize::new(64).unwrap(),
		}
	}
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
	pub shell: PathBuf,
	pub args: Vec<String>,
	pub keys: PathBuf,
	#[serde(default = "default_concurrency")]
	pub concurrency: NonZeroUsize,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
	#[serde(default)]
	pub global: GlobalConfig,
	pub routes: HashMap<String, RouteConfig>,
}

#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
	#[error("invalid route name: {0}")]
	InvalidRouteName(String),
	#[error("cannot stat shell for route {route}: {source}")]
	ShellStat {
		route: String,
		#[source]
		source: std::io::Error,
	},
	#[error("shell for route {route} is not a file: {}", .shell.display())]
	ShellNotFile { route: String, shell: PathBuf },
	#[error("shell for route {route} is not executable: {}", .shell.display())]
	ShellNotExecutable { route: String, shell: PathBuf },
}

impl Config {
	pub fn validate(&self) -> Result<(), ConfigError> {
		if self.routes.is_empty() {
			warn!("no routes configured; server will serve nothing");
		}
		for (name, route) in &self.routes {
			if !validate_route_name(name) {
				return Err(ConfigError::InvalidRouteName(name.clone()));
			}
			let metadata = std::fs::metadata(&route.shell).map_err(|e| ConfigError::ShellStat {
				route: name.clone(),
				source: e,
			})?;
			if !metadata.is_file() {
				return Err(ConfigError::ShellNotFile {
					route: name.clone(),
					shell: route.shell.clone(),
				});
			}

			// checks any execute bit (owner/group/other)
			let mode = metadata.permissions().mode() & 0o777;
			if mode & 0o111 == 0 {
				return Err(ConfigError::ShellNotExecutable {
					route: name.clone(),
					shell: route.shell.clone(),
				});
			}
		}
		Ok(())
	}
}

pub fn validate_route_name(name: &str) -> bool {
	if name.is_empty() {
		return false;
	}
	name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}
