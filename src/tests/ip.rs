use super::*;
use std::num::NonZeroUsize;

#[test]
fn test_resolve_client_ip_untrusted_peer_ignores_headers() {
	let mut headers = HeaderMap::new();
	headers.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
	headers.insert("x-real-ip", "5.6.7.8".parse().unwrap());
	let trusted = [ip("10.0.0.1")];
	assert_eq!(resolve_client_ip(peer("9.9.9.9"), &headers, &trusted), ip("9.9.9.9"));
}

#[test]
fn test_resolve_client_ip_forwarded_for_from_trusted_proxy() {
	let mut headers = HeaderMap::new();
	headers.insert("x-forwarded-for", "1.2.3.4, 10.0.0.1".parse().unwrap());
	let trusted = [ip("10.0.0.1")];
	assert_eq!(resolve_client_ip(peer("10.0.0.1"), &headers, &trusted), ip("1.2.3.4"));
}

#[test]
fn test_resolve_client_ip_real_ip_fallback() {
	let mut headers = HeaderMap::new();
	headers.insert("x-real-ip", "5.6.7.8".parse().unwrap());
	let trusted = [ip("10.0.0.1")];
	assert_eq!(resolve_client_ip(peer("10.0.0.1"), &headers, &trusted), ip("5.6.7.8"));
}

#[test]
fn test_resolve_client_ip_real_ip_rejects_trusted_proxy_value() {
	let mut headers = HeaderMap::new();
	headers.insert("x-real-ip", "10.0.0.1".parse().unwrap());
	let trusted = [ip("10.0.0.1")];
	assert_eq!(resolve_client_ip(peer("10.0.0.1"), &headers, &trusted), ip("10.0.0.1"));
}

#[test]
fn test_resolve_client_ip_forwarded_for_all_trusted_falls_back_to_real_ip() {
	let mut headers = HeaderMap::new();
	headers.insert("x-forwarded-for", "10.0.0.2, 10.0.0.1".parse().unwrap());
	headers.insert("x-real-ip", "5.6.7.8".parse().unwrap());
	let trusted = [ip("10.0.0.1"), ip("10.0.0.2")];
	assert_eq!(resolve_client_ip(peer("10.0.0.1"), &headers, &trusted), ip("5.6.7.8"));
}

#[test]
fn test_resolve_client_ip_forwarded_for_multiple_instances_ignores_spoofed_first() {
	let mut headers = HeaderMap::new();
	headers.append("x-forwarded-for", "6.6.6.6".parse().unwrap());
	headers.append("x-forwarded-for", "1.2.3.4".parse().unwrap());
	let trusted = [ip("10.0.0.1")];
	assert_eq!(resolve_client_ip(peer("10.0.0.1"), &headers, &trusted), ip("1.2.3.4"));
}

#[test]
fn test_resolve_client_ip_forwarded_for_multiple_instances_all_trusted_walks_back() {
	let mut headers = HeaderMap::new();
	headers.append("x-forwarded-for", "6.6.6.6, 1.2.3.4".parse().unwrap());
	headers.append("x-forwarded-for", "10.0.0.2, 10.0.0.1".parse().unwrap());
	let trusted = [ip("10.0.0.1"), ip("10.0.0.2")];
	assert_eq!(resolve_client_ip(peer("10.0.0.1"), &headers, &trusted), ip("1.2.3.4"));
}

#[test]
fn test_resolve_client_ip_real_ip_multiple_instances_rejected() {
	let mut headers = HeaderMap::new();
	headers.append("x-real-ip", "6.6.6.6".parse().unwrap());
	headers.append("x-real-ip", "5.6.7.8".parse().unwrap());
	let trusted = [ip("10.0.0.1")];
	assert_eq!(resolve_client_ip(peer("10.0.0.1"), &headers, &trusted), ip("10.0.0.1"));
}

#[test]
fn test_resolve_client_ip_no_headers_returns_peer() {
	let headers = HeaderMap::new();
	let trusted = [ip("10.0.0.1")];
	assert_eq!(resolve_client_ip(peer("10.0.0.1"), &headers, &trusted), ip("10.0.0.1"));
}

#[test]
fn test_normalize_ip_v4_unchanged() {
	assert_eq!(normalize_ip(ip("192.0.2.1")), ip("192.0.2.1"));
}

#[test]
fn test_normalize_ip_v6_truncated_to_64() {
	assert_eq!(normalize_ip(ip("2001:db8:1:2:3:4:5:6")), ip("2001:db8:1:2::"));
	assert_eq!(
		normalize_ip(ip("2001:db8:1:2:ffff:ffff:ffff:ffff")),
		normalize_ip(ip("2001:db8:1:2::1"))
	);
	assert_ne!(normalize_ip(ip("2001:db8:1:2::1")), normalize_ip(ip("2001:db8:1:3::1")));
}

#[test]
fn test_failure_tracker_blocks_ipv6_slash_64_rotation() {
	use crate::auth::FailureTracker;
	use std::time::Duration;

	let tracker = FailureTracker::new(
		3,
		Duration::from_secs(60),
		Duration::from_secs(60),
		NonZeroUsize::new(100_000).unwrap(),
	);
	tracker.record(ip("2001:db8:1:2::1"), false);
	tracker.record(ip("2001:db8:1:2::2"), false);
	tracker.record(ip("2001:db8:1:2::3"), false);
	assert!(tracker.is_blocked(ip("2001:db8:1:2::4")));
	assert!(!tracker.is_blocked(ip("2001:db8:1:3::1")));
}
