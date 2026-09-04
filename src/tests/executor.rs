use crate::config::RouteConfig;
use crate::executor::{ExecutionLimits, OutputLine, RouteExecution, output_until_exit};
use crate::route_state::RouteState;
use axum::response::sse::Event;
use futures_util::stream::{self, StreamExt};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

fn line_event(r#type: &'static str, line: &str) -> Result<Event, String> {
	Event::default()
		.json_data(OutputLine {
			r#type,
			line: line.to_string(),
		})
		.map_err(|e| format!("json error: {}", e))
}

fn debug_strings(events: &[Result<Event, String>]) -> Vec<String> {
	events.iter().map(|e| format!("{:?}", e)).collect()
}

fn exit_debug(code: i32) -> String {
	format!("{:?}", line_event("exit", &code.to_string()))
}

const GRACE: Duration = Duration::from_secs(2);

#[tokio::test]
async fn eof_then_exit_event() {
	let (tx, rx) = tokio::sync::oneshot::channel();
	let out = stream::iter(vec![line_event("stdout", "a"), line_event("stderr", "b")]).boxed();
	tx.send(0).unwrap();
	let events: Vec<_> = output_until_exit(out, rx, GRACE).collect().await;
	let got = debug_strings(&events);
	assert_eq!(got.len(), 3);
	assert_eq!(got[2], exit_debug(0));
}

#[tokio::test(start_paused = true)]
async fn hung_pipe_ends_after_grace() {
	let (tx, rx) = tokio::sync::oneshot::channel();
	let out = stream::iter(vec![line_event("stdout", "before daemon")])
		.chain(stream::pending())
		.boxed();
	tx.send(0).unwrap();
	let start = tokio::time::Instant::now();
	let events: Vec<_> = output_until_exit(out, rx, GRACE).collect().await;
	let got = debug_strings(&events);
	assert_eq!(got.len(), 2);
	assert_eq!(got[0], format!("{:?}", line_event("stdout", "before daemon")));
	assert_eq!(got[1], exit_debug(0));
	assert!(start.elapsed() <= GRACE + Duration::from_millis(100));
}

#[tokio::test(start_paused = true)]
async fn drains_remaining_output_within_grace() {
	let (tx, rx) = tokio::sync::oneshot::channel();
	tx.send(3).unwrap();
	let out = stream::iter(vec![line_event("stdout", "x"), line_event("stdout", "y")])
		.chain(stream::pending())
		.boxed();
	let events: Vec<_> = output_until_exit(out, rx, GRACE).collect().await;
	let got = debug_strings(&events);
	assert_eq!(got.len(), 3);
	assert_eq!(got[0], format!("{:?}", line_event("stdout", "x")));
	assert_eq!(got[1], format!("{:?}", line_event("stdout", "y")));
	assert_eq!(got[2], exit_debug(3));
}

#[tokio::test]
async fn dropped_exit_sender_yields_minus_one() {
	let (tx, rx) = tokio::sync::oneshot::channel::<i32>();
	drop(tx);
	let out = stream::iter(vec![line_event("stdout", "a")]).boxed();
	let events: Vec<_> = output_until_exit(out, rx, GRACE).collect().await;
	let got = debug_strings(&events);
	assert_eq!(got.len(), 2);
	assert_eq!(got[1], exit_debug(-1));
}

#[tokio::test(start_paused = true)]
async fn hung_pipe_and_late_exit() {
	let (tx, rx) = tokio::sync::oneshot::channel();
	let out = stream::pending().boxed();
	tokio::spawn(async move {
		tokio::time::sleep(Duration::from_secs(5)).await;
		tx.send(137).unwrap();
	});
	let events: Vec<_> = output_until_exit(out, rx, GRACE).collect().await;
	let got = debug_strings(&events);
	assert_eq!(got, vec![exit_debug(137)]);
}

#[tokio::test]
async fn executor_timeout_kills_long_running_child() {
	let route_config = RouteConfig {
		shell: std::path::PathBuf::from("/bin/sh"),
		args: vec![
			"-c".to_string(),
			"echo before-sleep && sleep 3600 && echo after-sleep".to_string(),
		],
		keys: std::path::PathBuf::from("/dev/null"),
		concurrency: NonZeroUsize::new(10).unwrap(),
	};
	let route_state = Arc::new(RouteState {
		config: route_config,
		keys: Arc::new(crate::auth::Keys { hashes: HashMap::new() }),
		semaphore: Arc::new(tokio::sync::Semaphore::new(10)),
	});
	let limits = ExecutionLimits {
		timeout_duration: Duration::from_millis(100),
		grace_duration: Duration::from_millis(50),
		drain_duration: Duration::from_millis(50),
		max_line_length: 4096,
	};
	let execution = RouteExecution::spawn("timeout-test", &route_state, limits)
		.await
		.unwrap();
	let start = tokio::time::Instant::now();
	let events: Vec<_> = execution.stream_output().collect().await;
	let elapsed = start.elapsed();
	let got = debug_strings(&events);
	assert!(!got.is_empty(), "should have at least one event, got {}", got.len());
	assert!(
		got.iter().any(|e| e.contains("before-sleep")),
		"should contain before-sleep output, got {:?}",
		got
	);
	assert!(
		elapsed < Duration::from_millis(500),
		"should finish within 500ms, took {:?}",
		elapsed
	);
}
