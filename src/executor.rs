use crate::route_state::RouteState;
use axum::{http::StatusCode, response::sse::Event};
use futures_util::stream::{self, Stream, StreamExt};
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, sigaction};
use nix::unistd::Pid;
use std::os::unix::process::ExitStatusExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tokio_util::codec::{FramedRead, LinesCodec};
use tracing::{Span, error, info, warn};

/// Execution limits loaded from `GlobalConfig`.
pub struct ExecutionLimits {
	pub timeout_duration: Duration,
	pub grace_duration: Duration,
	pub drain_duration: Duration,
	pub max_line_length: usize,
}

#[derive(serde::Serialize, Debug)]
pub struct OutputLine {
	pub r#type: &'static str,
	pub line: String,
}

/// Streams length-capped lines from `reader` as SSE events.
fn line_event_stream<R: tokio::io::AsyncRead + Unpin>(
	reader: R,
	r#type: &'static str,
	max_line_length: usize,
) -> impl Stream<Item = Result<Event, String>> {
	let framed = FramedRead::new(reader, LinesCodec::new_with_max_length(max_line_length));
	stream::unfold(Some(framed), move |state| async move {
		let mut framed = state?;
		match framed.next().await {
			Some(Ok(line)) => Some((
				Event::default()
					.json_data(OutputLine { r#type, line })
					.map_err(|e| format!("json error: {}", e)),
				Some(framed),
			)),
			Some(Err(e)) => {
				warn!(stream = r#type, error = %e, "read error");
				let error_event = Event::default()
					.json_data(OutputLine {
						r#type,
						line: format!("[stream truncated: {}]", e),
					})
					.map_err(|e| format!("json error: {}", e));
				// keep the framed reader alive to drain remaining data and avoid blocking the child
				Some((error_event, Some(framed)))
			}
			None => None,
		}
	})
}

/// Manages a spawned child process: spawns it, streams its output as SSE,
/// and enforces timeout and semaphore limits.
pub struct RouteExecution {
	child: tokio::process::Child,
	stdout: tokio::process::ChildStdout,
	stderr: tokio::process::ChildStderr,
	permit: tokio::sync::OwnedSemaphorePermit,
	limits: ExecutionLimits,
}

impl RouteExecution {
	/// Spawn the child process and begin streaming output.
	pub async fn spawn(
		route_name: &str,
		route_state: &Arc<RouteState>,
		limits: ExecutionLimits,
	) -> Result<Self, (StatusCode, String)> {
		// acquire route semaphore
		let permit = match route_state.semaphore.clone().try_acquire_owned() {
			Ok(p) => p,
			Err(_) => {
				warn!(route = %route_name, "route concurrency limit reached");
				return Err((
					StatusCode::SERVICE_UNAVAILABLE,
					"Route concurrency limit reached".to_string(),
				));
			}
		};

		// spawn (ignores SIGPIPE intentionally)
		let shell = route_state.config.shell.clone();
		let args = route_state.config.args.clone();
		let mut cmd = Command::new(&shell);
		cmd.args(&args)
			.stdout(std::process::Stdio::piped())
			.stderr(std::process::Stdio::piped())
			.process_group(0);

		unsafe {
			cmd.pre_exec(|| {
				let action = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());
				let _ = sigaction(nix::sys::signal::Signal::SIGPIPE, &action);
				Ok(())
			});
		}

		let mut child = cmd.spawn().map_err(|e| {
			error!(route = %route_name, error = %e, "failed to spawn");
			(StatusCode::INTERNAL_SERVER_ERROR, "Failed to execute shell".to_string())
		})?;

		info!(route = %route_name, pid = child.id(), "process spawned");
		let stdout = child.stdout.take().expect("stdout piped");
		let stderr = child.stderr.take().expect("stderr piped");

		Ok(Self {
			child,
			stdout,
			stderr,
			permit,
			limits,
		})
	}

	/// Set up the timeout task and return the SSE stream.
	pub fn stream_output(mut self) -> impl Stream<Item = Result<Event, String>> {
		let timeout_duration = self.limits.timeout_duration;
		let grace_duration = self.limits.grace_duration;

		let (exit_tx, exit_rx) = tokio::sync::oneshot::channel();

		let span = Span::current();
		tokio::spawn(async move {
			let _guard = span.enter();
			let mut exit_code: i32 = -1;
			match tokio::time::timeout(timeout_duration, self.child.wait()).await {
				Ok(Ok(status)) => {
					exit_code = exit_status_code(status);
					info!(exit_code, "process exited");
				}
				Ok(Err(e)) => {
					error!(error = %e, "failed to wait on child");
					signal_process_group(&self.child, nix::sys::signal::Signal::SIGKILL);
				}
				Err(_) => {
					error!(
						timeout_secs = timeout_duration.as_secs(),
						"timeout, killing process group"
					);
					signal_process_group(&self.child, nix::sys::signal::Signal::SIGTERM);
					match tokio::time::timeout(grace_duration, self.child.wait()).await {
						Ok(Ok(status)) => {
							exit_code = exit_status_code(status);
							info!(exit_code, signal = "SIGTERM", "process exited after signal");
						}
						Ok(Err(e)) => {
							error!(error = %e, "failed to wait on child after SIGTERM");
						}
						Err(_) => {
							signal_process_group(&self.child, nix::sys::signal::Signal::SIGKILL);
							let _ = self.child.kill().await;
						}
					}
				}
			}
			let _ = exit_tx.send(exit_code);
			drop(self.permit);
		});

		output_until_exit(
			stream::select(
				line_event_stream(self.stdout, "stdout", self.limits.max_line_length),
				line_event_stream(self.stderr, "stderr", self.limits.max_line_length),
			)
			.boxed(),
			exit_rx,
			self.limits.drain_duration,
		)
	}
}

fn signal_process_group(child: &tokio::process::Child, signal: nix::sys::signal::Signal) {
	if let Some(pid) = child.id()
		&& let Ok(pid) = i32::try_from(pid)
	{
		let pgid = Pid::from_raw(pid);
		let _ = nix::sys::signal::killpg(pgid, signal);
	}
}

/// The process exit code, 128 + signal if killed by a signal, or -1 if neither is available.
fn exit_status_code(status: std::process::ExitStatus) -> i32 {
	status.code().or_else(|| status.signal().map(|s| 128 + s)).unwrap_or(-1)
}

fn exit_event(code: i32) -> Result<Event, String> {
	Event::default()
		.json_data(OutputLine {
			r#type: "exit",
			line: code.to_string(),
		})
		.map_err(|e| format!("json error: {}", e))
}

/// Streams output events until the child exits, then drains remaining output for at most
/// `drain_grace` before emitting the exit event and ending. This guarantees the SSE stream
/// terminates even if a grandchild keeps the stdout/stderr pipes open after the child dies.
pub(crate) fn output_until_exit<S>(
	out: S,
	exit_rx: tokio::sync::oneshot::Receiver<i32>,
	drain_grace: Duration,
) -> impl Stream<Item = Result<Event, String>>
where
	S: Stream<Item = Result<Event, String>> + Unpin,
{
	enum Phase {
		Running(tokio::sync::oneshot::Receiver<i32>),
		Draining(i32, tokio::time::Instant),
		Done,
	}

	stream::unfold((out, Phase::Running(exit_rx)), move |(mut out, phase)| async move {
		match phase {
			Phase::Running(mut rx) => {
				tokio::select! {
					item = out.next() => match item {
						Some(ev) => Some((ev, (out, Phase::Running(rx)))),
						None => {
							let code = rx.await.unwrap_or(-1);
							Some((exit_event(code), (out, Phase::Done)))
						}
					},
					code = &mut rx => {
						let code = code.unwrap_or(-1);
						let deadline = tokio::time::Instant::now() + drain_grace;
						match tokio::time::timeout_at(deadline, out.next()).await {
							Ok(Some(ev)) => Some((ev, (out, Phase::Draining(code, deadline)))),
							_ => Some((exit_event(code), (out, Phase::Done))),
						}
					}
				}
			}
			Phase::Draining(code, deadline) => match tokio::time::timeout_at(deadline, out.next()).await {
				Ok(Some(ev)) => Some((ev, (out, Phase::Draining(code, deadline)))),
				_ => Some((exit_event(code), (out, Phase::Done))),
			},
			Phase::Done => None,
		}
	})
}
