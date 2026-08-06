use super::*;
use crate::auth::FailureTracker;
use std::num::NonZeroUsize;
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
	let temp_file = tempfile::NamedTempFile::new().unwrap();
	std::fs::write(
		temp_file.path(),
		"$y$j9T$xlKmMsoZxul/zvPXLC/Aj.$m0BFqZYiyDAF7bh/Tb3.CDTH5kgmBfBRhXbKAO0nco7\n",
	)
	.unwrap();
	let result = Keys::from_file(temp_file.path());
	assert!(result.is_err());
}

#[test]
fn test_keys_from_file_accepts_keyid_format() {
	let temp_file = tempfile::NamedTempFile::new().unwrap();
	std::fs::write(
		temp_file.path(),
		"a1b2c3d4:$y$j9T$xlKmMsoZxul/zvPXLC/Aj.$m0BFqZYiyDAF7bh/Tb3.CDTH5kgmBfBRhXbKAO0nco7\n",
	)
	.unwrap();
	let result = Keys::from_file(temp_file.path());
	assert!(result.is_ok());
}

#[test]
fn test_keys_from_file_rejects_invalid_hash() {
	let temp_file = tempfile::NamedTempFile::new().unwrap();
	std::fs::write(temp_file.path(), "a1b2c3d4:not-a-valid-hash\n").unwrap();
	let result = Keys::from_file(temp_file.path());
	assert!(result.is_err());
}

#[test]
fn test_keys_from_file_rejects_corrupted_yescrypt_hash() {
	let temp_file = tempfile::NamedTempFile::new().unwrap();
	std::fs::write(temp_file.path(), "a1b2c3d4:$pbkdf2$invalid\n").unwrap();
	let result = Keys::from_file(temp_file.path());
	assert!(result.is_err());
}

#[test]
fn test_keys_from_file_accepts_valid_hash() {
	let temp_file = tempfile::NamedTempFile::new().unwrap();
	let yescrypt = Yescrypt::default();
	let hash = yescrypt.hash_password(b"testpass").expect("hashing failed").to_string();
	std::fs::write(temp_file.path(), format!("testkey:{}\n", hash)).unwrap();
	let result = Keys::from_file(temp_file.path());
	assert!(result.is_ok());
	let keys = result.unwrap();
	assert!(keys.verify("testkey.testpass"));
}

#[test]
fn test_failure_tracker_blocks_after_threshold() {
	let tracker = FailureTracker::new(
		3,
		Duration::from_secs(60),
		Duration::from_secs(60),
		NonZeroUsize::new(100_000).unwrap(),
	);
	let addr = "127.0.0.1".parse::<IpAddr>().unwrap();
	tracker.record(addr, false);
	tracker.record(addr, false);
	tracker.record(addr, false);
	assert!(tracker.is_blocked(addr));
}

#[test]
fn test_failure_tracker_clears_on_success() {
	let tracker = FailureTracker::new(
		3,
		Duration::from_secs(60),
		Duration::from_secs(60),
		NonZeroUsize::new(100_000).unwrap(),
	);
	let addr = "127.0.0.1".parse::<IpAddr>().unwrap();
	tracker.record(addr, false);
	tracker.record(addr, false);
	tracker.record(addr, true);
	assert!(!tracker.is_blocked(addr));
}

#[test]
fn test_failure_tracker_success_only_clears_own_ip() {
	let tracker = FailureTracker::new(
		3,
		Duration::from_secs(60),
		Duration::from_secs(60),
		NonZeroUsize::new(100_000).unwrap(),
	);
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
	let tracker = FailureTracker::new(
		3,
		Duration::from_millis(50),
		Duration::from_millis(50),
		NonZeroUsize::new(100_000).unwrap(),
	);
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
	let tracker = FailureTracker::new(
		3,
		Duration::from_secs(60),
		Duration::from_secs(60),
		NonZeroUsize::new(100_000).unwrap(),
	);
	let addr = "127.0.0.1".parse::<IpAddr>().unwrap();
	tracker.record(addr, false);
	tracker.record(addr, false);
	tracker.record(addr, false);
	assert!(tracker.is_blocked(addr));
	tracker.prune();
	assert!(tracker.is_blocked(addr));
}

#[test]
fn test_failure_tracker_eviction_never_evicts_blocked() {
	let tracker = FailureTracker::new(
		3,
		Duration::from_secs(60),
		Duration::from_secs(60),
		NonZeroUsize::new(2).unwrap(),
	);
	let blocked = "10.0.0.1".parse::<IpAddr>().unwrap();
	tracker.record(blocked, false);
	tracker.record(blocked, false);
	tracker.record(blocked, false);
	assert!(tracker.is_blocked(blocked));
	for i in 0..100u8 {
		tracker.record(format!("10.0.1.{}", i).parse::<IpAddr>().unwrap(), false);
	}
	assert!(tracker.is_blocked(blocked));
}

#[test]
fn test_failure_tracker_eviction_at_capacity_evicts_non_blocked() {
	let tracker = FailureTracker::new(
		3,
		Duration::from_secs(60),
		Duration::from_secs(60),
		NonZeroUsize::new(2).unwrap(),
	);
	let a = "10.0.0.1".parse::<IpAddr>().unwrap();
	let b = "10.0.0.2".parse::<IpAddr>().unwrap();
	let c = "10.0.0.3".parse::<IpAddr>().unwrap();
	tracker.record(a, false);
	tracker.record(b, false);
	tracker.record(c, false);
	tracker.record(c, false);
	tracker.record(c, false);
	assert!(tracker.is_blocked(c));
	assert!(!tracker.has_recent_failures(a));
}

#[test]
fn test_failure_tracker_refresh_extends_block() {
	let tracker = FailureTracker::new(
		3,
		Duration::from_millis(200),
		Duration::from_millis(200),
		NonZeroUsize::new(100_000).unwrap(),
	);
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

#[test]
fn test_success_does_not_clear_active_block() {
	let tracker = FailureTracker::new(
		3,
		Duration::from_secs(60),
		Duration::from_secs(60),
		NonZeroUsize::new(100_000).unwrap(),
	);
	let addr = "127.0.0.1".parse::<IpAddr>().unwrap();
	tracker.record(addr, false);
	tracker.record(addr, false);
	tracker.record(addr, false);
	assert!(tracker.is_blocked(addr));
	tracker.record(addr, true);
	assert!(tracker.is_blocked(addr));
}

#[test]
fn test_lazy_block_expiry_via_record_after_window() {
	let tracker = FailureTracker::new(
		3,
		Duration::from_millis(50),
		Duration::from_millis(50),
		NonZeroUsize::new(100_000).unwrap(),
	);
	let addr = "127.0.0.1".parse::<IpAddr>().unwrap();
	tracker.record(addr, false);
	tracker.record(addr, false);
	tracker.record(addr, false);
	assert!(tracker.is_blocked(addr));
	std::thread::sleep(Duration::from_millis(60));
	assert!(!tracker.is_blocked(addr));
	tracker.record(addr, false);
	assert!(!tracker.is_blocked(addr));
}
