use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;

fn default_auth_header() -> String {
	"x-api-key".to_string()
}

fn default_timeout() -> u64 {
	900
}

#[derive(Deserialize, Clone, Debug)]
pub struct GlobalConfig {
	#[serde(default = "default_auth_header")]
	pub auth_header: String,
	#[serde(default = "default_timeout")]
	pub timeout: u64,
	#[serde(default)]
	pub trusted_proxies: Vec<IpAddr>,
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
pub struct RouteConfig {
	pub shell: String,
	pub args: Vec<String>,
	pub keys: String,
	#[serde(default = "default_concurrency")]
	pub concurrency: usize,
}

fn default_concurrency() -> usize {
	1
}

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
	#[serde(default)]
	pub global: GlobalConfig,
	pub routes: HashMap<String, RouteConfig>,
}

pub fn validate_route_name(name: &str) -> bool {
	name.chars().all(|c| !matches!(c, '/' | '{' | '}' | ' ' | '\t' | '\n' | '\r'))
}
