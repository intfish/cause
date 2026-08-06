use super::*;
use tower_governor::key_extractor::KeyExtractor;

#[test]
fn test_key_extractor_no_connect_info_fails() {
	let extractor = TrustedProxyKeyExtractor {
		trusted_proxies: vec![],
	};
	let req = axum::http::Request::builder().body(()).unwrap();
	assert!(extractor.extract(&req).is_err());
}

#[test]
fn test_key_extractor_untrusted_peer_ignores_headers() {
	let extractor = TrustedProxyKeyExtractor {
		trusted_proxies: vec![ip("10.0.0.1")],
	};
	let req = request_with_peer("9.9.9.9:1234", &[("x-forwarded-for", "1.2.3.4")]);
	assert_eq!(extractor.extract(&req).unwrap(), ip("9.9.9.9"));
}

#[test]
fn test_key_extractor_trusted_peer_uses_forwarded_for() {
	let extractor = TrustedProxyKeyExtractor {
		trusted_proxies: vec![ip("10.0.0.1")],
	};
	let req = request_with_peer("10.0.0.1:1234", &[("x-forwarded-for", "1.2.3.4, 10.0.0.1")]);
	assert_eq!(extractor.extract(&req).unwrap(), ip("1.2.3.4"));
}

#[test]
fn test_key_extractor_normalizes_ipv6_to_64() {
	let extractor = TrustedProxyKeyExtractor {
		trusted_proxies: vec![],
	};
	let req = request_with_peer("[2001:db8:1:2:3:4:5:6]:1234", &[]);
	assert_eq!(extractor.extract(&req).unwrap(), ip("2001:db8:1:2::"));
}
