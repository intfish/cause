use super::*;
use crate::config::{Config, GlobalConfig};
use crate::handler::{AppState, acquire_auth_permit, register_inflight};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

async fn state_with(f: impl FnOnce(&mut GlobalConfig)) -> Arc<AppState> {
	let mut global = GlobalConfig::default();
	f(&mut global);
	let config = Config {
		global,
		routes: HashMap::new(),
	};
	Arc::new(AppState::from_config(config).await.unwrap())
}

#[test]
fn test_failure_tracker_has_recent_failures() {
	use crate::auth::FailureTracker;

	let tracker = FailureTracker::new(
		3,
		Duration::from_secs(60),
		Duration::from_secs(60),
		NonZeroUsize::new(100_000).unwrap(),
	);
	let addr = ip("10.0.0.1");
	assert!(!tracker.has_recent_failures(addr));
	tracker.record(addr, false);
	assert!(tracker.has_recent_failures(addr));
	tracker.record(addr, true);
	assert!(!tracker.has_recent_failures(addr));
}

#[tokio::test]
async fn test_inflight_cap_and_guard_drop() {
	let state = state_with(|_| {}).await;
	let addr = ip("10.0.0.2");
	let g1 = register_inflight(&state, addr).unwrap();
	let _g2 = register_inflight(&state, addr).unwrap();
	assert!(register_inflight(&state, addr).is_none());
	assert!(register_inflight(&state, ip("10.0.0.3")).is_some());
	drop(g1);
	assert!(register_inflight(&state, addr).is_some());
}

#[tokio::test]
async fn test_clean_client_gets_reserved_permit_when_general_saturated() {
	let state = state_with(|g| {
		g.auth_semaphore_size = std::num::NonZeroUsize::new(2).unwrap();
		g.auth_acquire_timeout_ms = 50;
	})
	.await;
	let _held = state.auth_semaphore.clone().try_acquire_owned().unwrap();
	assert!(acquire_auth_permit(&state, false).await.is_none());
	assert!(acquire_auth_permit(&state, true).await.is_some());
}

#[tokio::test]
async fn test_acquire_waits_for_released_permit() {
	let state = state_with(|g| {
		g.auth_semaphore_size = std::num::NonZeroUsize::new(2).unwrap();
		g.auth_acquire_timeout_ms = 2000;
	})
	.await;
	let held = state.auth_semaphore.clone().try_acquire_owned().unwrap();
	tokio::spawn(async move {
		tokio::time::sleep(Duration::from_millis(20)).await;
		drop(held);
	});
	assert!(acquire_auth_permit(&state, false).await.is_some());
}

#[tokio::test]
async fn test_queue_depth_bound_fast_fails() {
	let state = state_with(|g| {
		g.auth_acquire_timeout_ms = 5000;
		g.max_auth_queue_depth = std::num::NonZeroUsize::new(1).unwrap();
	})
	.await;
	state.auth_waiters.store(1, Ordering::SeqCst);
	let start = std::time::Instant::now();
	assert!(acquire_auth_permit(&state, false).await.is_none());
	assert!(start.elapsed() < Duration::from_millis(500));
}
