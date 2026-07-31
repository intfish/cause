use crate::auth::{FailureTracker, Keys};
use std::net::IpAddr;
use std::time::Duration;
use yescrypt::PasswordHasher;
use yescrypt::PasswordVerifier;
use yescrypt::Yescrypt;

#[test]
fn test_keys_verify_valid() {
	let yescrypt = Yescrypt::default();
	let hash_obj = yescrypt.hash_password(b"super53cr37").expect("hashing failed");
	let hash_str = hash_obj.to_string();
	let key_id = "testkey1";
	let keys = Keys {
		hashes: {
			let mut m = std::collections::HashMap::new();
			m.insert(key_id.to_string(), vec![hash_str.clone()]);
			m
		},
	};
	assert!(yescrypt.verify_password(b"super53cr37", hash_str.as_str()).is_ok());
	assert!(keys.verify(&format!("{}.{}", key_id, "super53cr37")));
}

#[test]
fn test_keys_verify_wrong_secret() {
	let yescrypt = Yescrypt::default();
	let hash = yescrypt.hash_password(b"correct").expect("hashing failed").to_string();
	let key_id = "testkey2";
	let keys = Keys {
		hashes: {
			let mut m = std::collections::HashMap::new();
			m.insert(key_id.to_string(), vec![hash]);
			m
		},
	};
	assert!(!keys.verify(&format!("{}.{}", key_id, "wrong")));
}

#[test]
fn test_keys_verify_unknown_id() {
	let keys = Keys {
		hashes: {
			let mut m = std::collections::HashMap::new();
			m.insert("otherid".to_string(), vec!["$y$j9T$hash".to_string()]);
			m
		},
	};
	assert!(!keys.verify("unknownid.secret"));
}

#[test]
fn test_keys_verify_no_dot() {
	let keys = Keys {
		hashes: {
			let mut m = std::collections::HashMap::new();
			m.insert("id".to_string(), vec!["$y$j9T$hash".to_string()]);
			m
		},
	};
	assert!(!keys.verify("noseparator"));
}

#[test]
fn test_keys_from_file_rejects_malformed() {
	let dir = std::env::temp_dir();
	let path = dir.join("cause_test_malformed_keys");
	std::fs::write(
		&path,
		"$y$j9T$xlKmMsoZxul/zvPXLC/Aj.$m0BFqZYiyDAF7bh/Tb3.CDTH5kgmBfBRhXbKAO0nco7\n",
	)
	.unwrap();
	let result = Keys::from_file(path.to_str().unwrap());
	assert!(result.is_err());
	std::fs::remove_file(&path).ok();
}

#[test]
fn test_keys_from_file_accepts_keyid_format() {
	let dir = std::env::temp_dir();
	let path = dir.join("cause_test_keyid_keys");
	std::fs::write(
		&path,
		"a1b2c3d4:$y$j9T$xlKmMsoZxul/zvPXLC/Aj.$m0BFqZYiyDAF7bh/Tb3.CDTH5kgmBfBRhXbKAO0nco7\n",
	)
	.unwrap();
	let result = Keys::from_file(path.to_str().unwrap());
	assert!(result.is_ok());
	std::fs::remove_file(&path).ok();
}

#[test]
fn test_failure_tracker_blocks_after_threshold() {
	let tracker = FailureTracker::new(3, Duration::from_secs(60));
	let addr = "127.0.0.1".parse::<IpAddr>().unwrap();
	tracker.record(addr, false);
	tracker.record(addr, false);
	tracker.record(addr, false);
	assert!(tracker.is_blocked(addr));
}

#[test]
fn test_failure_tracker_clears_on_success() {
	let tracker = FailureTracker::new(3, Duration::from_secs(60));
	let addr = "127.0.0.1".parse::<IpAddr>().unwrap();
	tracker.record(addr, false);
	tracker.record(addr, false);
	tracker.record(addr, true);
	assert!(!tracker.is_blocked(addr));
}

#[test]
fn test_failure_tracker_success_only_clears_own_ip() {
	let tracker = FailureTracker::new(3, Duration::from_secs(60));
	let addr_a = "10.0.0.1".parse::<IpAddr>().unwrap();
	let addr_b = "10.0.0.2".parse::<IpAddr>().unwrap();
	tracker.record(addr_a, false);
	tracker.record(addr_a, false);
	tracker.record(addr_a, false);
	assert!(tracker.is_blocked(addr_a));
	tracker.record(addr_b, true);
	assert!(tracker.is_blocked(addr_a));
}

#[test]
fn test_failure_tracker_prune_removes_stale() {
	let tracker = FailureTracker::new(3, Duration::from_millis(50));
	let addr = "127.0.0.1".parse::<IpAddr>().unwrap();
	tracker.record(addr, false);
	tracker.record(addr, false);
	tracker.record(addr, false);
	assert!(tracker.is_blocked(addr));
	std::thread::sleep(Duration::from_millis(100));
	tracker.prune();
	assert!(!tracker.is_blocked(addr));
}

#[test]
fn test_failure_tracker_prune_keeps_fresh() {
	let tracker = FailureTracker::new(3, Duration::from_secs(60));
	let addr = "127.0.0.1".parse::<IpAddr>().unwrap();
	tracker.record(addr, false);
	tracker.record(addr, false);
	tracker.record(addr, false);
	assert!(tracker.is_blocked(addr));
	tracker.prune();
	assert!(tracker.is_blocked(addr));
}

#[test]
fn test_failure_tracker_refresh_extends_block() {
	let tracker = FailureTracker::new(3, Duration::from_millis(200));
	let addr = "127.0.0.1".parse::<IpAddr>().unwrap();
	tracker.record(addr, false);
	tracker.record(addr, false);
	tracker.record(addr, false);
	assert!(tracker.is_blocked(addr));
	std::thread::sleep(Duration::from_millis(150));
	assert!(tracker.is_blocked(addr));
	tracker.refresh_block(addr);
	assert!(tracker.is_blocked(addr));
	std::thread::sleep(Duration::from_millis(50));
	assert!(tracker.is_blocked(addr));
	std::thread::sleep(Duration::from_millis(160));
	assert!(!tracker.is_blocked(addr));
}
