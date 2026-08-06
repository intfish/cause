mod auth;
mod config;
mod executor;
mod handler;
mod ip;
mod rate_limit;

use crate::auth::Keys;
use crate::config::validate_route_name;
use crate::net::{normalize_ip, resolve_client_ip};
use crate::rate_limit::TrustedProxyKeyExtractor;
use axum::extract::ConnectInfo;
use axum::http::HeaderMap;
use std::net::IpAddr;
use std::net::SocketAddr;

fn peer(ip: &str) -> IpAddr {
	ip.parse().unwrap()
}

fn ip(s: &str) -> IpAddr {
	s.parse().unwrap()
}

fn request_with_peer(peer: &str, headers: &[(&str, &str)]) -> axum::http::Request<()> {
	let mut req = axum::http::Request::builder();
	for (k, v) in headers {
		req = req.header(*k, *v);
	}
	let mut req = req.body(()).unwrap();
	let addr: SocketAddr = peer.parse().unwrap();
	req.extensions_mut().insert(ConnectInfo(addr));
	req
}
