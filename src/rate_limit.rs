use crate::auth::FailureTracker;
use crate::net::{normalize_ip, resolve_client_ip};
use anyhow::Context;
use axum::{Router, extract::ConnectInfo};
use std::net::SocketAddr;
use std::num::{NonZeroU32, NonZeroU64};
use std::sync::Arc;
use std::time::Duration;

/// Wraps the router with a governor rate-limiting layer and spawns a background
/// task to clean up rate limiter and failure tracker storage every `cleanup_interval`.
pub fn rate_limited<K>(
	router: Router,
	key_extractor: K,
	failure_tracker: Arc<FailureTracker>,
	per_second: NonZeroU64,
	burst_size: NonZeroU32,
	cleanup_interval: Duration,
) -> anyhow::Result<Router>
where
	K: tower_governor::key_extractor::KeyExtractor + Send + Sync + 'static,
	K::Key: Send + Sync + 'static,
{
	let governor_conf = Arc::new(
		tower_governor::governor::GovernorConfigBuilder::default()
			.per_second(per_second.get())
			.burst_size(burst_size.get())
			.key_extractor(key_extractor)
			.finish()
			.context("failed to build governor config")?,
	);
	let limiter = governor_conf.limiter().clone();
	tokio::spawn(async move {
		loop {
			tokio::time::sleep(cleanup_interval).await;
			limiter.retain_recent();
			failure_tracker.prune();
		}
	});
	Ok(router.layer(tower_governor::GovernorLayer::new(governor_conf)))
}

/// Custom key extractor that respects trusted proxies.
/// Only trusts X-Forwarded-For / X-Real-IP when the peer is a trusted proxy.
///
/// The reverse proxy must overwrite (not append to / pass through) `X-Real-IP`;
/// values resolving to a trusted proxy IP are ignored.
#[derive(Clone)]
pub struct TrustedProxyKeyExtractor {
	pub trusted_proxies: Vec<std::net::IpAddr>,
}

impl tower_governor::key_extractor::KeyExtractor for TrustedProxyKeyExtractor {
	type Key = std::net::IpAddr;

	fn extract<T>(&self, req: &axum::http::Request<T>) -> Result<Self::Key, tower_governor::errors::GovernorError> {
		let peer_ip = req
			.extensions()
			.get::<ConnectInfo<SocketAddr>>()
			.map(|ci| ci.0.ip())
			.ok_or_else(|| tower_governor::errors::GovernorError::UnableToExtractKey)?;
		Ok(normalize_ip(resolve_client_ip(
			peer_ip,
			req.headers(),
			&self.trusted_proxies,
		)))
	}
}
