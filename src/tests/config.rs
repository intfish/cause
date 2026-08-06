use super::*;

#[test]
fn test_validate_route_name() {
	assert!(validate_route_name("deploy-prod_1"));
	assert!(!validate_route_name(""));
	assert!(!validate_route_name("a/b"));
	assert!(!validate_route_name("a b"));
	assert!(!validate_route_name("caf\u{e9}"));
	assert!(!validate_route_name("\u{663}"));
}
