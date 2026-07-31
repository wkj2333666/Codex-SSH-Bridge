use std::collections::HashMap;
use std::ffi::OsString;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
    DuplexStream,
};
use tokio::process::Command;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_util::sync::CancellationToken;

use super::dispatcher::dispatcher_command;
use super::frame::{Frame, FrameKind, read_frame, write_frame};
use super::helper::{
    BootstrapStatus, HelperArtifact, HelperIdentity, helper_artifact, helper_bytes, helper_command,
    helper_identity, parse_bootstrap_status, persistent_helper_command,
};
use super::{HelperMode, SshPolicy, build_ssh_argv};
use crate::capability::{Capability, ShellKind, ShellSelection};
use crate::config::EffectiveLimits;
use crate::error::{BridgeError, BridgeResult, ErrorCode};

const CANCEL_GRACE: Duration = Duration::from_millis(200);
const OUTPUT_FORWARD_QUEUE_CAPACITY: usize = 16;
const OUTPUT_FORWARD_CHUNK_BYTES: usize = 64 * 1024;
const OUTPUT_FORWARD_BACKPRESSURE_GRACE: Duration = Duration::from_millis(25);
const STARTUP_CLEANUP_GRACE: Duration = Duration::from_millis(100);

#[derive(Debug)]
pub(crate) struct SessionRequest {
    pub(crate) action: SessionAction,
    pub(crate) env: std::collections::BTreeMap<String, Option<String>>,
    pub(crate) timeout: Duration,
    pub(crate) admission_deadline: Instant,
    pub(crate) response_timeout: Duration,
    pub(crate) stdout_limit: u64,
    pub(crate) stderr_limit: u64,
    pub(crate) output: Option<SessionOutput>,
}

#[derive(Debug)]
pub(crate) enum SessionAction {
    Command {
        command: String,
        cwd: String,
        shell: ShellSelection,
        login_shell: Option<String>,
        stdin: Option<Vec<u8>>,
    },
    Search {
        root: String,
        query: Vec<u8>,
        globs: Vec<String>,
        max_results: usize,
        binary: bool,
    },
    Job {
        request: Vec<u8>,
    },
}

#[derive(Debug)]
pub(crate) struct SessionOutput {
    pub(crate) stdout: DuplexStream,
    pub(crate) stderr: DuplexStream,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionResult {
    pub(crate) request_id: u64,
    pub(crate) status: i32,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) stdout_truncated: bool,
    pub(crate) stderr_truncated: bool,
    pub(crate) elapsed_ms: u64,
    pub(crate) remote_process_may_continue: bool,
    pub(crate) timed_out: bool,
}

#[derive(Clone)]
pub(crate) struct HostSession {
    inner: Arc<SessionInner>,
}

struct SessionInner {
    host: String,
    helper_mode: HelperMode,
    max_payload: usize,
    max_output_bytes: u64,
    tx: mpsc::Sender<Outbound>,
    pending: Mutex<HashMap<u64, PendingRequest>>,
    next_id: AtomicU64,
    closed: AtomicBool,
    retired: AtomicBool,
    process_group: AtomicI32,
    writer_task: Mutex<Option<JoinHandle<()>>>,
    reader_task: Mutex<Option<JoinHandle<()>>>,
    child_task: Mutex<Option<JoinHandle<()>>>,
}

struct PendingRequest {
    started: Instant,
    ready: Option<oneshot::Sender<()>>,
    stdout_limit: usize,
    stderr_limit: usize,
    aggregate_limit: usize,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_seen: u64,
    stderr_seen: u64,
    stdout_truncated: bool,
    stderr_truncated: bool,
    stdout_sink: Option<OutputForwarder>,
    stderr_sink: Option<OutputForwarder>,
    sender: oneshot::Sender<BridgeResult<SessionResult>>,
}

struct OutputForwarder {
    sender: Option<mpsc::Sender<Vec<u8>>>,
    cancel: Option<CancellationToken>,
    failed: Arc<AtomicBool>,
}

impl OutputForwarder {
    fn new(mut sink: DuplexStream) -> Self {
        let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(OUTPUT_FORWARD_QUEUE_CAPACITY);
        let cancel = CancellationToken::new();
        let worker_cancel = cancel.clone();
        let failed = Arc::new(AtomicBool::new(false));
        let worker_failed = Arc::clone(&failed);
        tokio::spawn(async move {
            while let Some(bytes) = receiver.recv().await {
                let result = tokio::select! {
                    biased;
                    () = worker_cancel.cancelled() => return,
                    result = sink.write_all(&bytes) => result,
                };
                if result.is_err() {
                    worker_failed.store(true, Ordering::Release);
                    return;
                }
            }
        });
        Self {
            sender: Some(sender),
            cancel: Some(cancel),
            failed,
        }
    }

    async fn forward(&mut self, bytes: &[u8]) -> bool {
        let Some(sender) = &self.sender else {
            return false;
        };
        for chunk in bytes.chunks(OUTPUT_FORWARD_CHUNK_BYTES) {
            if !matches!(
                timeout(
                    OUTPUT_FORWARD_BACKPRESSURE_GRACE,
                    sender.send(chunk.to_vec())
                )
                .await,
                Ok(Ok(()))
            ) {
                self.failed.store(true, Ordering::Release);
                if let Some(cancel) = self.cancel.take() {
                    cancel.cancel();
                }
                self.sender.take();
                return false;
            }
        }
        true
    }

    fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    fn finish(mut self) -> bool {
        drop(self.sender.take());
        drop(self.cancel.take());
        self.failed()
    }
}

impl Drop for OutputForwarder {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            cancel.cancel();
        }
    }
}

struct Outbound {
    frames: Vec<Frame>,
}

enum ConnectionStart {
    Shell,
    Temporary {
        artifact: HelperArtifact,
        bytes: Vec<u8>,
    },
    Persistent {
        artifact: HelperArtifact,
        bytes: Vec<u8>,
        identity: HelperIdentity,
    },
}

struct StartupProcessGuard {
    process_group: i32,
    armed: bool,
}

#[derive(Clone)]
struct ConnectionRuntime {
    executable: OsString,
    environment: std::collections::BTreeMap<OsString, OsString>,
    deadline: Instant,
}

impl StartupProcessGuard {
    fn new(process_group: i32) -> Self {
        Self {
            process_group,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StartupProcessGuard {
    fn drop(&mut self) {
        if self.armed {
            signal_process_group(self.process_group, libc::SIGKILL);
        }
    }
}

impl ConnectionStart {
    fn helper_arch(&self) -> Option<&'static str> {
        match self {
            Self::Shell => None,
            Self::Temporary { artifact, .. } | Self::Persistent { artifact, .. } => {
                Some(artifact.arch)
            }
        }
    }

    const fn mode(&self) -> HelperMode {
        match self {
            Self::Shell => HelperMode::Shell,
            Self::Temporary { .. } => HelperMode::Temporary,
            Self::Persistent { .. } => HelperMode::Persistent,
        }
    }
}

impl HostSession {
    #[allow(dead_code)]
    pub(crate) async fn connect(
        policy: SshPolicy,
        host: String,
        limits: EffectiveLimits,
        cancel: CancellationToken,
    ) -> BridgeResult<Self> {
        Self::connect_with(
            policy,
            host,
            limits,
            OsString::from("/usr/bin/ssh"),
            std::collections::BTreeMap::new(),
            cancel,
        )
        .await
    }

    pub(crate) async fn connect_with(
        policy: SshPolicy,
        host: String,
        limits: EffectiveLimits,
        executable: OsString,
        environment: std::collections::BTreeMap<OsString, OsString>,
        cancel: CancellationToken,
    ) -> BridgeResult<Self> {
        let deadline = Instant::now() + Duration::from_millis(limits.connect_timeout_ms.max(1));
        let timeout_host = host.clone();
        let connect = Self::connect_with_mode(
            policy,
            host,
            limits,
            cancel.clone(),
            ConnectionStart::Shell,
            ConnectionRuntime {
                executable,
                environment,
                deadline,
            },
        );
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(cancelled_error(&timeout_host, false)),
            result = timeout_at(deadline, connect) => match result {
                Ok(result) => result,
                Err(_) => Err(connect_timeout_error(&timeout_host, "SSH session setup timed out")),
            }
        }
    }

    pub(crate) async fn connect_with_capability(
        policy: SshPolicy,
        host: String,
        limits: EffectiveLimits,
        executable: OsString,
        environment: std::collections::BTreeMap<OsString, OsString>,
        capability: &Capability,
        cancel: CancellationToken,
    ) -> BridgeResult<Self> {
        let deadline = Instant::now() + Duration::from_millis(limits.connect_timeout_ms.max(1));
        let timeout_host = host.clone();
        let outer_cancel = cancel.clone();
        let connect = async move {
            let runtime = ConnectionRuntime {
                executable,
                environment,
                deadline,
            };
            let helper = helper_artifact(capability).and_then(|artifact| {
                helper_bytes(&artifact).ok().and_then(|bytes| {
                    helper_identity(&artifact, &bytes)
                        .ok()
                        .map(|identity| (artifact, bytes, identity))
                })
            });
            let Some((artifact, bytes, identity)) = helper else {
                return Self::connect_with_mode(
                    policy,
                    host,
                    limits,
                    cancel,
                    ConnectionStart::Shell,
                    runtime,
                )
                .await;
            };
            let fallback_policy = policy.clone();
            let fallback_host = host.clone();
            match Self::connect_with_mode(
                policy,
                host,
                limits,
                cancel.clone(),
                ConnectionStart::Persistent {
                    artifact: artifact.clone(),
                    bytes: bytes.clone(),
                    identity,
                },
                runtime.clone(),
            )
            .await
            {
                Ok(session) => Ok(session),
                Err(error) if helper_startup_fallback_allowed(&error, &cancel) => {
                    match Self::connect_with_mode(
                        fallback_policy.clone(),
                        fallback_host.clone(),
                        limits,
                        cancel.clone(),
                        ConnectionStart::Temporary { artifact, bytes },
                        runtime.clone(),
                    )
                    .await
                    {
                        Ok(session) => Ok(session),
                        Err(error) if helper_startup_fallback_allowed(&error, &cancel) => {
                            Self::connect_with_mode(
                                fallback_policy,
                                fallback_host,
                                limits,
                                cancel,
                                ConnectionStart::Shell,
                                runtime,
                            )
                            .await
                        }
                        Err(error) => Err(error),
                    }
                }
                Err(error) => Err(error),
            }
        };
        tokio::select! {
            biased;
            () = outer_cancel.cancelled() => Err(cancelled_error(&timeout_host, false)),
            result = timeout_at(deadline, connect) => match result {
                Ok(result) => result,
                Err(_) => Err(connect_timeout_error(&timeout_host, "SSH session setup timed out")),
            }
        }
    }

    async fn connect_with_mode(
        policy: SshPolicy,
        host: String,
        limits: EffectiveLimits,
        cancel: CancellationToken,
        start: ConnectionStart,
        runtime: ConnectionRuntime,
    ) -> BridgeResult<Self> {
        if limits.max_frame_bytes == 0 {
            return Err(BridgeError::invalid_argument(
                "SSH session frame limit must be positive",
            ));
        }
        if runtime.deadline <= Instant::now() {
            return Err(connect_timeout_error(&host, "SSH session setup timed out"));
        }
        let helper_arch = start.helper_arch();
        let command = match &start {
            ConnectionStart::Shell => dispatcher_command(limits.max_frame_bytes)?,
            ConnectionStart::Temporary { bytes, .. } => {
                helper_command(limits.max_frame_bytes, bytes.len())?
            }
            ConnectionStart::Persistent { identity, .. } => {
                persistent_helper_command(limits.max_frame_bytes, identity)?
            }
        };
        let argv = build_ssh_argv(&policy, &host, &command);
        let mut child_command = Command::new(runtime.executable);
        child_command
            .args(argv)
            .envs(runtime.environment)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // SAFETY: setpgid is async-signal-safe and receives no borrowed data.
        unsafe {
            child_command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        if cancel.is_cancelled() {
            return Err(cancelled_error(&host, false));
        }
        let mut child = child_command.spawn().map_err(BridgeError::io)?;
        let process_group = child.id().ok_or_else(|| {
            BridgeError::new(ErrorCode::Io, "SSH session child has no process id", false)
        })? as i32;
        let mut startup_guard = StartupProcessGuard::new(process_group);
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| BridgeError::io("SSH session stdout pipe is missing"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| BridgeError::io("SSH session stderr pipe is missing"))?;
        tokio::spawn(drain_stderr(stderr));
        let mut output = BufReader::new(stdout);
        let helper_bootstrap_profile = (!matches!(start, ConnectionStart::Shell)).then(|| {
            crate::bridge_profile_span!(crate::profile::ProfileEvent {
                phase: "helper_bootstrap",
                host: Some(host.as_str()),
                request_id: None,
                class: Some("cold"),
                elapsed_us: 0,
                bytes: None,
            })
        });
        let helper_probe_profile = matches!(start, ConnectionStart::Persistent { .. }).then(|| {
            crate::bridge_profile_span!(crate::profile::ProfileEvent {
                phase: "helper_install_probe",
                host: Some(host.as_str()),
                request_id: None,
                class: Some("cold"),
                elapsed_us: 0,
                bytes: None,
            })
        });
        match &start {
            ConnectionStart::Persistent { bytes, .. } => {
                let status = tokio::select! {
                    biased;
                    () = cancel.cancelled() => {
                        cleanup_startup_child(&mut child, &mut startup_guard).await;
                        return Err(cancelled_error(&host, false));
                    }
                    result = timeout_at(
                        runtime.deadline,
                        read_bootstrap_status_line(&mut output),
                    ) => match result {
                        Ok(Ok(status)) => status,
                        Ok(Err(error)) => {
                            cleanup_startup_child(&mut child, &mut startup_guard).await;
                            return Err(error);
                        }
                        Err(_) => {
                            cleanup_startup_child(&mut child, &mut startup_guard).await;
                            return Err(connect_timeout_error(
                                &host,
                                "persistent helper bootstrap timed out",
                            ));
                        }
                    }
                };
                drop(helper_probe_profile);
                if status == BootstrapStatus::Need {
                    let helper_upload_profile =
                        crate::bridge_profile_span!(crate::profile::ProfileEvent {
                            phase: "helper_install_upload",
                            host: Some(host.as_str()),
                            request_id: None,
                            class: Some("cold"),
                            elapsed_us: 0,
                            bytes: Some(bytes.len() as u64),
                        });
                    write_helper_bytes(
                        &mut child,
                        &host,
                        bytes,
                        runtime.deadline,
                        &cancel,
                        &mut startup_guard,
                    )
                    .await?;
                    drop(helper_upload_profile);
                }
            }
            ConnectionStart::Temporary { bytes, .. } => {
                drop(helper_probe_profile);
                write_helper_bytes(
                    &mut child,
                    &host,
                    bytes,
                    runtime.deadline,
                    &cancel,
                    &mut startup_guard,
                )
                .await?;
            }
            ConnectionStart::Shell => drop(helper_probe_profile),
        }
        drop(helper_bootstrap_profile);
        let helper_handshake_profile = (!matches!(start, ConnectionStart::Shell)).then(|| {
            crate::bridge_profile_span!(crate::profile::ProfileEvent {
                phase: "helper_handshake",
                host: Some(host.as_str()),
                request_id: None,
                class: Some("cold"),
                elapsed_us: 0,
                bytes: None,
            })
        });
        let hello = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                cleanup_startup_child(&mut child, &mut startup_guard).await;
                return Err(cancelled_error(&host, false));
            }
            result = timeout_at(runtime.deadline, read_frame(&mut output, limits.max_frame_bytes)) => {
                match result {
                    Ok(Ok(Some(frame))) => frame,
                    Ok(Ok(None)) => {
                        cleanup_startup_child(&mut child, &mut startup_guard).await;
                        return Err(startup_error(&host, "SSH session closed before handshake"));
                    }
                    Ok(Err(error)) => {
                        cleanup_startup_child(&mut child, &mut startup_guard).await;
                        return Err(startup_error(&host, &error.to_string()));
                    }
                    Err(_) => {
                        cleanup_startup_child(&mut child, &mut startup_guard).await;
                        return Err(connect_timeout_error(&host, "SSH dispatcher handshake timed out"));
                    }
                }
            }
        };
        drop(helper_handshake_profile);
        if hello.kind == FrameKind::Error {
            cleanup_startup_child(&mut child, &mut startup_guard).await;
            let message = String::from_utf8_lossy(&hello.payload).into_owned();
            if message.starts_with("DISPATCHER_CAPABILITY_MISSING=") {
                let mut error =
                    BridgeError::new(ErrorCode::RemoteCapabilityMissing, message, false);
                error.details.host = Some(host);
                return Err(error);
            }
            return Err(startup_error(&host, &message));
        }
        if hello.kind != FrameKind::HelloAck
            || hello.request_id != 0
            || !valid_handshake(&hello.payload, helper_arch)
        {
            cleanup_startup_child(&mut child, &mut startup_guard).await;
            return Err(startup_error(&host, "invalid SSH dispatcher handshake"));
        }

        let helper_mode = start.mode();
        let (tx, rx) = mpsc::channel(64);
        let inner = Arc::new(SessionInner {
            host,
            helper_mode,
            max_payload: limits.max_frame_bytes,
            max_output_bytes: limits.max_output_bytes,
            tx,
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            closed: AtomicBool::new(false),
            retired: AtomicBool::new(false),
            process_group: AtomicI32::new(process_group),
            writer_task: Mutex::new(None),
            reader_task: Mutex::new(None),
            child_task: Mutex::new(None),
        });
        let writer_inner = Arc::downgrade(&inner);
        let writer_task = tokio::spawn(writer_loop(rx, child.stdin.take(), writer_inner));
        let reader_inner = Arc::downgrade(&inner);
        let reader_task = tokio::spawn(reader_loop(output, reader_inner));
        let child_inner = Arc::downgrade(&inner);
        let child_task = tokio::spawn(child_loop(child, child_inner));
        *inner.writer_task.lock().await = Some(writer_task);
        *inner.reader_task.lock().await = Some(reader_task);
        *inner.child_task.lock().await = Some(child_task);
        startup_guard.disarm();
        Ok(Self { inner })
    }

    pub(crate) async fn execute(
        &self,
        request: SessionRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<SessionResult> {
        let started = Instant::now();
        let request_id = self.inner.next_request_id()?;
        let _request_profile = crate::bridge_profile_span!(crate::profile::ProfileEvent {
            phase: "session_request",
            host: Some(self.inner.host.as_str()),
            request_id: Some(request_id),
            class: None,
            elapsed_us: 0,
            bytes: None,
        });
        let frames = build_request_frames(request_id, &request, self.inner.max_payload)?;
        let (sender, mut receiver) = oneshot::channel();
        let (ready, mut ready_receiver) = oneshot::channel();
        let (stdout_sink, stderr_sink) = request
            .output
            .map(|output| {
                (
                    Some(OutputForwarder::new(output.stdout)),
                    Some(OutputForwarder::new(output.stderr)),
                )
            })
            .unwrap_or((None, None));
        let pending = PendingRequest {
            started,
            ready: Some(ready),
            stdout_limit: usize::try_from(request.stdout_limit)
                .map_err(|_| BridgeError::invalid_argument("stdout limit is too large"))?,
            stderr_limit: usize::try_from(request.stderr_limit)
                .map_err(|_| BridgeError::invalid_argument("stderr limit is too large"))?,
            aggregate_limit: usize::try_from(
                request
                    .stdout_limit
                    .saturating_add(request.stderr_limit)
                    .min(self.inner.max_output_bytes),
            )
            .map_err(|_| BridgeError::invalid_argument("output limit is too large"))?,
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_seen: 0,
            stderr_seen: 0,
            stdout_truncated: false,
            stderr_truncated: false,
            stdout_sink,
            stderr_sink,
            sender,
        };
        self.inner.pending.lock().await.insert(request_id, pending);
        let helper_command_profile = if self.inner.helper_mode != HelperMode::Shell {
            Some(crate::bridge_profile_span!(crate::profile::ProfileEvent {
                phase: "helper_command_spawn",
                host: Some(self.inner.host.as_str()),
                request_id: Some(request_id),
                class: None,
                elapsed_us: 0,
                bytes: None,
            }))
        } else {
            None
        };
        let send = tokio::select! {
            biased;
            () = cancel.cancelled() => Err(cancelled_error(&self.inner.host, false)),
            result = timeout_at(request.admission_deadline, self.inner.send(Outbound { frames })) => {
                match result {
                    Ok(result) => result,
                    Err(_) => Err(timeout_error(&self.inner.host, false)),
                }
            }
        };
        if let Err(error) = send {
            drop(helper_command_profile);
            self.inner.pending.lock().await.remove(&request_id);
            return Err(error);
        }
        drop(helper_command_profile);
        // Request admission includes the local writer queue, transport, and
        // complete remote request decoding. The remote READY frame is the
        // boundary at which command execution (and its watchdog) begins.
        tokio::select! {
            biased;
            result = &mut receiver => {
                return result.map_err(|_| transport_error(&self.inner.host, true))?;
            }
            result = &mut ready_receiver => {
                result.map_err(|_| transport_error(&self.inner.host, true))?;
            }
            () = cancel.cancelled() => {
                return self.abort_request(request_id, &mut receiver, false).await;
            }
            () = tokio::time::sleep_until(request.admission_deadline) => {
                return self.abort_request(request_id, &mut receiver, true).await;
            }
        }
        // Queueing and request transfer must not consume the command's response
        // allowance. READY aligns this deadline with the remote watchdog.
        let response_deadline = Instant::now() + request.response_timeout;
        tokio::select! {
            biased;
            result = &mut receiver => result.map_err(|_| transport_error(&self.inner.host, true))?,
            () = cancel.cancelled() => self.abort_request(request_id, &mut receiver, false).await,
            () = tokio::time::sleep_until(response_deadline) => {
                self.abort_request(request_id, &mut receiver, true).await
            },
        }
    }

    async fn abort_request(
        &self,
        request_id: u64,
        receiver: &mut oneshot::Receiver<BridgeResult<SessionResult>>,
        timed_out: bool,
    ) -> BridgeResult<SessionResult> {
        let cancel_delivery = timeout(
            CANCEL_GRACE,
            self.inner.send(Outbound {
                frames: vec![Frame {
                    kind: FrameKind::Cancel,
                    request_id,
                    payload: Vec::new(),
                }],
            }),
        )
        .await;
        if !matches!(cancel_delivery, Ok(Ok(()))) {
            self.inner
                .transport_failure(transport_error(&self.inner.host, true))
                .await;
            return Err(if timed_out {
                timeout_error(&self.inner.host, true)
            } else {
                cancelled_error(&self.inner.host, true)
            });
        }
        match timeout(CANCEL_GRACE, receiver).await {
            Ok(Ok(Ok(result))) => Err(if timed_out {
                timeout_error(&self.inner.host, result.remote_process_may_continue)
            } else {
                cancelled_error(&self.inner.host, result.remote_process_may_continue)
            }),
            Ok(Ok(Err(_))) => Err(if timed_out {
                timeout_error(&self.inner.host, true)
            } else {
                cancelled_error(&self.inner.host, true)
            }),
            // Cancellation is request-scoped only while the dispatcher confirms
            // it promptly. If an accepted CANCEL does not produce an EXIT, the
            // shared transport is no longer making provable progress; keeping
            // it around leaves later requests queued behind a wedged session.
            Ok(Err(_)) | Err(_) => {
                self.inner.retired.store(true, Ordering::Release);
                self.inner
                    .transport_failure(transport_error(&self.inner.host, true))
                    .await;
                Err(if timed_out {
                    timeout_error(&self.inner.host, true)
                } else {
                    cancelled_error(&self.inner.host, true)
                })
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) async fn close(&self) -> BridgeResult<()> {
        self.inner.shutdown().await;
        Ok(())
    }

    pub(crate) fn helper_mode(&self) -> HelperMode {
        self.inner.helper_mode
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    pub(crate) fn is_reusable(&self) -> bool {
        !self.is_closed() && !self.inner.retired.load(Ordering::Acquire)
    }

    pub(crate) fn retire_idle(&self) {
        self.inner.retired.store(true, Ordering::Release);
        if !self.inner.closed.swap(true, Ordering::AcqRel) {
            terminate_process_group(self.inner.process_group.load(Ordering::Acquire));
        }
    }

    #[cfg(test)]
    pub(crate) fn wedged_for_test(host: &str, max_payload: usize, max_output_bytes: u64) -> Self {
        let (tx, mut rx) = mpsc::channel::<Outbound>(64);
        let writer_task = tokio::spawn(async move { while rx.recv().await.is_some() {} });
        let inner = Arc::new(SessionInner {
            host: host.to_owned(),
            helper_mode: HelperMode::Persistent,
            max_payload,
            max_output_bytes,
            tx,
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            closed: AtomicBool::new(false),
            retired: AtomicBool::new(false),
            process_group: AtomicI32::new(0),
            writer_task: Mutex::new(Some(writer_task)),
            reader_task: Mutex::new(None),
            child_task: Mutex::new(None),
        });
        Self { inner }
    }
}

async fn write_helper_bytes(
    child: &mut tokio::process::Child,
    host: &str,
    bytes: &[u8],
    deadline: Instant,
    cancel: &CancellationToken,
    startup_guard: &mut StartupProcessGuard,
) -> BridgeResult<()> {
    enum UploadStop {
        Completed(std::io::Result<()>),
        Cancelled,
        Deadline,
    }

    let stop = {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| BridgeError::io("SSH session stdin pipe is missing"))?;
        let upload = async {
            stdin.write_all(bytes).await?;
            stdin.flush().await
        };
        tokio::select! {
            biased;
            () = cancel.cancelled() => UploadStop::Cancelled,
            result = timeout_at(deadline, upload) => match result {
                Ok(result) => UploadStop::Completed(result),
                Err(_) => UploadStop::Deadline,
            }
        }
    };
    match stop {
        UploadStop::Completed(Ok(())) => Ok(()),
        UploadStop::Completed(Err(error)) => {
            cleanup_startup_child(child, startup_guard).await;
            Err(startup_error(host, &error.to_string()))
        }
        UploadStop::Cancelled => {
            cleanup_startup_child(child, startup_guard).await;
            Err(cancelled_error(host, false))
        }
        UploadStop::Deadline => {
            cleanup_startup_child(child, startup_guard).await;
            Err(connect_timeout_error(host, "SSH helper upload timed out"))
        }
    }
}

async fn cleanup_startup_child(
    child: &mut tokio::process::Child,
    startup_guard: &mut StartupProcessGuard,
) {
    signal_process_group(startup_guard.process_group, libc::SIGTERM);
    let child_exited = timeout(STARTUP_CLEANUP_GRACE, child.wait()).await.is_ok();
    signal_process_group(startup_guard.process_group, libc::SIGKILL);
    if !child_exited {
        let _ = timeout(STARTUP_CLEANUP_GRACE, child.wait()).await;
    }
    startup_guard.disarm();
}

async fn read_bootstrap_status_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
) -> BridgeResult<BootstrapStatus> {
    let mut status = Vec::with_capacity(32);
    let read = reader
        .read_until(b'\n', &mut status)
        .await
        .map_err(BridgeError::io)?;
    if read == 0 {
        return Err(BridgeError::new(
            ErrorCode::ProtocolError,
            "persistent helper bootstrap closed before status",
            false,
        ));
    }
    parse_bootstrap_status(&status)
}

impl SessionInner {
    fn next_request_id(&self) -> BridgeResult<u64> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        if id == 0 {
            return Err(BridgeError::new(
                ErrorCode::ProtocolError,
                "SSH session request ID space is exhausted",
                false,
            ));
        }
        Ok(id)
    }

    async fn send(&self, outbound: Outbound) -> BridgeResult<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(transport_error(&self.host, true));
        }
        self.tx
            .send(outbound)
            .await
            .map_err(|_| transport_error(&self.host, true))
    }

    async fn shutdown(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = self
            .tx
            .send(Outbound {
                frames: vec![Frame {
                    kind: FrameKind::Close,
                    request_id: 0,
                    payload: Vec::new(),
                }],
            })
            .await;
        self.fail_all(transport_error(&self.host, true)).await;
        terminate_process_group(self.process_group.load(Ordering::Acquire));
    }

    async fn fail_all(&self, error: BridgeError) {
        let mut pending = self.pending.lock().await;
        for (_, request) in pending.drain() {
            let _ = request.sender.send(Err(error.clone()));
        }
    }

    async fn fail_request(&self, request_id: u64, error: BridgeError) {
        if let Some(request) = self.pending.lock().await.remove(&request_id) {
            let _ = request.sender.send(Err(error));
        }
    }

    async fn transport_failure(&self, error: BridgeError) {
        self.closed.store(true, Ordering::Release);
        self.fail_all(error).await;
        terminate_process_group(self.process_group.load(Ordering::Acquire));
    }
}

async fn writer_loop(
    mut receiver: mpsc::Receiver<Outbound>,
    stdin: Option<impl AsyncWrite + Unpin + Send + 'static>,
    inner: Weak<SessionInner>,
) {
    let Some(mut stdin) = stdin else {
        if let Some(inner) = inner.upgrade() {
            inner
                .transport_failure(transport_error(&inner.host, true))
                .await;
        }
        return;
    };
    while let Some(outbound) = receiver.recv().await {
        for frame in outbound.frames {
            let upgraded = inner.upgrade();
            let max_payload = upgraded.as_ref().map_or(0, |inner| inner.max_payload);
            let _frame_profile = upgraded.as_ref().and_then(|inner| {
                if inner.helper_mode != HelperMode::Shell {
                    Some(crate::bridge_profile_span!(crate::profile::ProfileEvent {
                        phase: "helper_frame_write",
                        host: Some(inner.host.as_str()),
                        request_id: Some(frame.request_id),
                        class: None,
                        elapsed_us: 0,
                        bytes: Some(frame.payload.len() as u64),
                    }))
                } else {
                    None
                }
            });
            if max_payload == 0 || write_frame(&mut stdin, &frame, max_payload).await.is_err() {
                if let Some(inner) = inner.upgrade() {
                    inner
                        .transport_failure(transport_error(&inner.host, true))
                        .await;
                }
                return;
            }
        }
        if stdin.flush().await.is_err() {
            if let Some(inner) = inner.upgrade() {
                inner
                    .transport_failure(transport_error(&inner.host, true))
                    .await;
            }
            return;
        }
    }
}

async fn reader_loop<R: AsyncBufRead + Unpin>(mut reader: R, inner: Weak<SessionInner>) {
    let max_payload = inner.upgrade().map_or(0, |inner| inner.max_payload);
    loop {
        let result = read_frame(&mut reader, max_payload).await;
        match result {
            Ok(Some(frame)) => {
                let Some(inner) = inner.upgrade() else { return };
                if let Err(error) = dispatch_frame(&inner, frame).await {
                    inner.transport_failure(error).await;
                    return;
                }
            }
            Ok(None) => {
                if let Some(inner) = inner.upgrade() {
                    inner
                        .transport_failure(transport_error(&inner.host, true))
                        .await;
                }
                return;
            }
            Err(error) => {
                if let Some(inner) = inner.upgrade() {
                    inner
                        .transport_failure(protocol_error(&inner.host, &error.to_string()))
                        .await;
                }
                return;
            }
        }
    }
}

async fn child_loop(mut child: tokio::process::Child, inner: Weak<SessionInner>) {
    let _ = child.wait().await;
    if let Some(inner) = inner.upgrade()
        && !inner.closed.swap(true, Ordering::AcqRel)
    {
        inner.fail_all(transport_error(&inner.host, true)).await;
    }
}

async fn drain_stderr(mut stderr: impl AsyncRead + Unpin) {
    let mut buffer = [0u8; 4096];
    loop {
        match stderr.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

async fn dispatch_frame(inner: &Arc<SessionInner>, frame: Frame) -> BridgeResult<()> {
    match frame.kind {
        FrameKind::Ready => {
            let ready = {
                let mut pending = inner.pending.lock().await;
                let request = pending.get_mut(&frame.request_id).ok_or_else(|| {
                    protocol_error(&inner.host, "dispatcher returned an unknown request ID")
                })?;
                request.ready.take().ok_or_else(|| {
                    protocol_error(&inner.host, "dispatcher returned duplicate READY")
                })?
            };
            let _ = ready.send(());
            Ok(())
        }
        FrameKind::Stdout | FrameKind::Stderr => {
            let mut pending = inner.pending.lock().await;
            let request = pending.get_mut(&frame.request_id).ok_or_else(|| {
                protocol_error(&inner.host, "dispatcher returned an unknown request ID")
            })?;
            if frame.kind == FrameKind::Stdout {
                let _output_profile = if inner.helper_mode != HelperMode::Shell {
                    Some(crate::bridge_profile_span!(crate::profile::ProfileEvent {
                        phase: "helper_output_drain",
                        host: Some(inner.host.as_str()),
                        request_id: Some(frame.request_id),
                        class: None,
                        elapsed_us: 0,
                        bytes: Some(frame.payload.len() as u64),
                    }))
                } else {
                    None
                };
                let aggregate_used =
                    request.stdout_seen.saturating_add(request.stderr_seen) as usize;
                let remaining = request
                    .stdout_limit
                    .saturating_sub(request.stdout_seen as usize)
                    .min(request.aggregate_limit.saturating_sub(aggregate_used));
                if frame.payload.len() > remaining {
                    request.stdout_truncated = true;
                }
                let allowed = remaining.min(frame.payload.len());
                let write_failed = if let Some(sink) = request.stdout_sink.as_mut() {
                    !sink.forward(&frame.payload[..allowed]).await
                } else {
                    request.stdout.extend_from_slice(&frame.payload[..allowed]);
                    false
                };
                if write_failed {
                    request.stdout_sink.take();
                    request.stdout_truncated = true;
                    request.stdout_limit = request.stdout_seen as usize;
                }
                request.stdout_seen = request
                    .stdout_seen
                    .saturating_add(frame.payload.len() as u64);
            } else {
                let _output_profile = if inner.helper_mode != HelperMode::Shell {
                    Some(crate::bridge_profile_span!(crate::profile::ProfileEvent {
                        phase: "helper_output_drain",
                        host: Some(inner.host.as_str()),
                        request_id: Some(frame.request_id),
                        class: None,
                        elapsed_us: 0,
                        bytes: Some(frame.payload.len() as u64),
                    }))
                } else {
                    None
                };
                let aggregate_used =
                    request.stdout_seen.saturating_add(request.stderr_seen) as usize;
                let remaining = request
                    .stderr_limit
                    .saturating_sub(request.stderr_seen as usize)
                    .min(request.aggregate_limit.saturating_sub(aggregate_used));
                if frame.payload.len() > remaining {
                    request.stderr_truncated = true;
                }
                let allowed = remaining.min(frame.payload.len());
                let write_failed = if let Some(sink) = request.stderr_sink.as_mut() {
                    !sink.forward(&frame.payload[..allowed]).await
                } else {
                    request.stderr.extend_from_slice(&frame.payload[..allowed]);
                    false
                };
                if write_failed {
                    request.stderr_sink.take();
                    request.stderr_truncated = true;
                    request.stderr_limit = request.stderr_seen as usize;
                }
                request.stderr_seen = request
                    .stderr_seen
                    .saturating_add(frame.payload.len() as u64);
            }
            Ok(())
        }
        FrameKind::Exit => {
            let _exit_profile = if inner.helper_mode != HelperMode::Shell {
                Some(crate::bridge_profile_span!(crate::profile::ProfileEvent {
                    phase: "helper_exit",
                    host: Some(inner.host.as_str()),
                    request_id: Some(frame.request_id),
                    class: None,
                    elapsed_us: 0,
                    bytes: Some(frame.payload.len() as u64),
                }))
            } else {
                None
            };
            let (
                status,
                stdout_truncated,
                stderr_truncated,
                remote_process_may_continue,
                timed_out,
            ) = parse_exit(&frame.payload)
                .map_err(|message| protocol_error(&inner.host, &message))?;
            let mut request = inner
                .pending
                .lock()
                .await
                .remove(&frame.request_id)
                .ok_or_else(|| {
                    protocol_error(
                        &inner.host,
                        "dispatcher returned an unknown exit request ID",
                    )
                })?;
            let stdout_forward_failed = request
                .stdout_sink
                .take()
                .is_some_and(OutputForwarder::finish);
            let stderr_forward_failed = request
                .stderr_sink
                .take()
                .is_some_and(OutputForwarder::finish);
            let result = SessionResult {
                request_id: frame.request_id,
                status,
                stdout: request.stdout,
                stderr: request.stderr,
                stdout_truncated: request.stdout_truncated
                    || stdout_forward_failed
                    || stdout_truncated,
                stderr_truncated: request.stderr_truncated
                    || stderr_forward_failed
                    || stderr_truncated,
                elapsed_ms: elapsed_ms(request.started.elapsed()),
                remote_process_may_continue,
                timed_out,
            };
            let _ = request.sender.send(Ok(result));
            Ok(())
        }
        FrameKind::Error => {
            let message = String::from_utf8_lossy(&frame.payload).trim().to_owned();
            let error = if message.starts_with("DISPATCHER_CAPABILITY_MISSING=") {
                BridgeError::new(ErrorCode::RemoteCapabilityMissing, message, false)
            } else {
                protocol_error(&inner.host, &message)
            };
            if frame.request_id == 0 {
                return Err(error);
            }
            inner.fail_request(frame.request_id, error).await;
            Ok(())
        }
        FrameKind::HelloAck => Err(protocol_error(
            &inner.host,
            "unexpected SSH dispatcher handshake frame",
        )),
        FrameKind::Hello
        | FrameKind::Open
        | FrameKind::Data
        | FrameKind::Cancel
        | FrameKind::Close => Err(protocol_error(
            &inner.host,
            "unexpected SSH dispatcher frame",
        )),
    }
}

fn build_request_frames(
    request_id: u64,
    request: &SessionRequest,
    max_payload: usize,
) -> BridgeResult<Vec<Frame>> {
    if !request.env.is_empty() {
        return Err(BridgeError::invalid_argument(
            "per-request environment overrides are not supported by this dispatcher",
        ));
    }
    match &request.action {
        SessionAction::Command {
            command,
            cwd,
            shell,
            login_shell,
            stdin,
        } => build_command_request_frames(
            request_id,
            request,
            command,
            cwd,
            shell,
            login_shell.as_deref(),
            stdin.as_deref().unwrap_or_default(),
            max_payload,
        ),
        SessionAction::Search {
            root,
            query,
            globs,
            max_results,
            binary,
        } => build_search_request_frames(
            request_id,
            request,
            root,
            query,
            globs,
            *max_results,
            *binary,
            max_payload,
        ),
        SessionAction::Job { request: body } => {
            build_job_request_frames(request_id, body, max_payload)
        }
    }
}

fn build_job_request_frames(
    request_id: u64,
    body: &[u8],
    max_payload: usize,
) -> BridgeResult<Vec<Frame>> {
    if body.is_empty() {
        return Err(BridgeError::invalid_argument(
            "session Job request must not be empty",
        ));
    }
    if body.len() > max_payload {
        return Err(BridgeError::new(
            ErrorCode::RequestTooLarge,
            "session Job request exceeds the configured frame limit",
            false,
        ));
    }
    let metadata = format!("operation=job\nrequest_length={}\n", body.len());
    if metadata.len() > max_payload {
        return Err(BridgeError::new(
            ErrorCode::RequestTooLarge,
            "session Job metadata exceeds the configured frame limit",
            false,
        ));
    }
    Ok(vec![
        Frame {
            kind: FrameKind::Open,
            request_id,
            payload: metadata.into_bytes(),
        },
        Frame {
            kind: FrameKind::Data,
            request_id,
            payload: body.to_vec(),
        },
    ])
}

#[allow(clippy::too_many_arguments)]
fn build_command_request_frames(
    request_id: u64,
    request: &SessionRequest,
    command: &str,
    cwd: &str,
    shell: &ShellSelection,
    login_shell: Option<&str>,
    stdin: &[u8],
    max_payload: usize,
) -> BridgeResult<Vec<Frame>> {
    if cwd.as_bytes().contains(&0) || command.as_bytes().contains(&0) {
        return Err(BridgeError::invalid_argument(
            "NUL is not representable in a session cwd or command",
        ));
    }
    let cwd = cwd.as_bytes();
    let command = command.as_bytes();
    for (name, bytes) in [
        ("cwd", cwd.len()),
        ("command", command.len()),
        ("stdin", stdin.len()),
    ] {
        if bytes > max_payload {
            return Err(BridgeError::new(
                ErrorCode::RequestTooLarge,
                format!("session {name} exceeds the configured frame limit"),
                false,
            ));
        }
    }
    let (shell, login_shell) = match &shell.shell {
        ShellKind::Bash { .. } => ("bash", ""),
        ShellKind::PosixSh => ("sh", ""),
        ShellKind::Login => {
            let login_shell = login_shell.ok_or_else(|| {
                BridgeError::new(
                    ErrorCode::RemoteCapabilityMissing,
                    "remote account login shell was not supplied to the SSH session",
                    false,
                )
            })?;
            if !login_shell.starts_with('/')
                || login_shell.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(BridgeError::invalid_argument(
                    "remote account login shell path is invalid",
                ));
            }
            ("login", login_shell)
        }
    };
    let metadata = format!(
        "shell={shell}\ncwd_length={}\ncommand_length={}\nstdin_length={}\nlogin_shell={login_shell}\ntimeout_ms={}\nstdout_limit={}\nstderr_limit={}\n",
        cwd.len(),
        command.len(),
        stdin.len(),
        request.timeout.as_millis(),
        request.stdout_limit,
        request.stderr_limit,
    );
    if metadata.len() > max_payload {
        return Err(BridgeError::new(
            ErrorCode::RequestTooLarge,
            "session metadata exceeds the configured frame limit",
            false,
        ));
    }
    let mut frames = vec![Frame {
        kind: FrameKind::Open,
        request_id,
        payload: metadata.into_bytes(),
    }];
    frames.push(Frame {
        kind: FrameKind::Data,
        request_id,
        payload: cwd.to_vec(),
    });
    frames.push(Frame {
        kind: FrameKind::Data,
        request_id,
        payload: command.to_vec(),
    });
    if !stdin.is_empty() {
        frames.push(Frame {
            kind: FrameKind::Data,
            request_id,
            payload: stdin.to_vec(),
        });
    }
    Ok(frames)
}

#[allow(clippy::too_many_arguments)]
fn build_search_request_frames(
    request_id: u64,
    request: &SessionRequest,
    root: &str,
    query: &[u8],
    globs: &[String],
    max_results: usize,
    binary: bool,
    max_payload: usize,
) -> BridgeResult<Vec<Frame>> {
    if root.as_bytes().contains(&0) || query.is_empty() {
        return Err(BridgeError::invalid_argument(
            "native search root must not contain NUL and query must not be empty",
        ));
    }
    let mut glob_bytes = Vec::new();
    for glob in globs {
        if glob.as_bytes().contains(&0) {
            return Err(BridgeError::invalid_argument(
                "native search glob must not contain NUL",
            ));
        }
        glob_bytes.extend_from_slice(glob.as_bytes());
        glob_bytes.push(0);
    }
    for (name, bytes) in [
        ("root", root.len()),
        ("query", query.len()),
        ("globs", glob_bytes.len()),
    ] {
        if bytes > max_payload {
            return Err(BridgeError::new(
                ErrorCode::RequestTooLarge,
                format!("session search {name} exceeds the configured frame limit"),
                false,
            ));
        }
    }
    let metadata = format!(
        "operation=search\nroot_length={}\nquery_length={}\nglobs_length={}\nmax_results={max_results}\nbinary={}\ntimeout_ms={}\nstdout_limit={}\nstderr_limit={}\n",
        root.len(),
        query.len(),
        glob_bytes.len(),
        u8::from(binary),
        request.timeout.as_millis(),
        request.stdout_limit,
        request.stderr_limit,
    );
    if metadata.len() > max_payload {
        return Err(BridgeError::new(
            ErrorCode::RequestTooLarge,
            "session search metadata exceeds the configured frame limit",
            false,
        ));
    }
    Ok(vec![
        Frame {
            kind: FrameKind::Open,
            request_id,
            payload: metadata.into_bytes(),
        },
        Frame {
            kind: FrameKind::Data,
            request_id,
            payload: root.as_bytes().to_vec(),
        },
        Frame {
            kind: FrameKind::Data,
            request_id,
            payload: query.to_vec(),
        },
        Frame {
            kind: FrameKind::Data,
            request_id,
            payload: glob_bytes,
        },
    ])
}

fn parse_exit(payload: &[u8]) -> Result<(i32, bool, bool, bool, bool), String> {
    let text = std::str::from_utf8(payload).map_err(|_| "dispatcher EXIT payload is not UTF-8")?;
    let mut lines = text.lines();
    let status = lines
        .next()
        .ok_or("dispatcher EXIT payload is missing status")?
        .parse::<i32>()
        .map_err(|_| "dispatcher EXIT status is invalid")?;
    let stdout = parse_bool(
        lines
            .next()
            .ok_or("dispatcher EXIT payload is incomplete")?,
    )?;
    let stderr = parse_bool(
        lines
            .next()
            .ok_or("dispatcher EXIT payload is incomplete")?,
    )?;
    let may_continue = match lines.next() {
        None => false,
        Some(value) => parse_bool(value)?,
    };
    let timed_out = match lines.next() {
        None => false,
        Some(value) => parse_bool(value)?,
    };
    if lines.next().is_some() {
        return Err("dispatcher EXIT payload has extra fields".to_owned());
    }
    Ok((status, stdout, stderr, may_continue, timed_out))
}

fn parse_bool(value: &str) -> Result<bool, String> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err("dispatcher EXIT truncation flag is invalid".to_owned()),
    }
}

fn startup_error(host: &str, message: &str) -> BridgeError {
    let mut error = BridgeError::new(
        ErrorCode::ProtocolError,
        format!("SSH dispatcher startup failed: {message}"),
        false,
    );
    error.details.host = Some(host.to_owned());
    error
}

fn helper_startup_fallback_allowed(error: &BridgeError, cancel: &CancellationToken) -> bool {
    !cancel.is_cancelled()
        && !matches!(
            error.code,
            ErrorCode::Cancelled
                | ErrorCode::ConnectTimeout
                | ErrorCode::InvalidArgument
                | ErrorCode::RemoteCapabilityMissing
        )
}

fn valid_handshake(payload: &[u8], helper_arch: Option<&str>) -> bool {
    let payload = String::from_utf8_lossy(payload);
    let fields: HashMap<&str, &str> = payload
        .split(';')
        .filter_map(|field| field.split_once('='))
        .collect();
    match helper_arch {
        Some(expected_arch) => {
            fields.get("protocol") == Some(&"codex-ssh-helper/1")
                && fields.get("version") == Some(&"1")
                && fields.get("arch") == Some(&expected_arch)
        }
        None => fields.get("protocol") == Some(&"codex-ssh-dispatcher/1"),
    }
}

fn protocol_error(host: &str, message: &str) -> BridgeError {
    let mut error = BridgeError::new(
        ErrorCode::ProtocolError,
        format!("SSH dispatcher protocol error: {message}"),
        false,
    );
    error.details.host = Some(host.to_owned());
    error
}

fn transport_error(host: &str, may_continue: bool) -> BridgeError {
    let mut error = BridgeError::new(
        ErrorCode::Io,
        "SSH dispatcher transport closed unexpectedly",
        false,
    );
    error.details.host = Some(host.to_owned());
    error.details.remote_process_may_continue = Some(may_continue);
    error
}

fn cancelled_error(host: &str, may_continue: bool) -> BridgeError {
    let mut error = BridgeError::new(ErrorCode::Cancelled, "SSH operation was cancelled", false);
    error.details.host = Some(host.to_owned());
    error.details.remote_process_may_continue = Some(may_continue);
    error
}

fn timeout_error(host: &str, may_continue: bool) -> BridgeError {
    let mut error = BridgeError::new(ErrorCode::CommandTimeout, "remote command timed out", false);
    error.details.host = Some(host.to_owned());
    error.details.remote_process_may_continue = Some(may_continue);
    error
}

fn terminate_process_group(process_group: i32) {
    signal_process_group(process_group, libc::SIGTERM);
}

fn signal_process_group(process_group: i32, signal: i32) {
    if process_group <= 0 {
        return;
    }
    // SAFETY: kill accepts a process-group ID and does not retain pointers.
    unsafe {
        let _ = libc::kill(-process_group, signal);
    }
}

fn connect_timeout_error(host: &str, message: &str) -> BridgeError {
    let mut error = BridgeError::new(ErrorCode::ConnectTimeout, message, true);
    error.details.host = Some(host.to_owned());
    error.details.remote_process_may_continue = Some(false);
    error
}

fn elapsed_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use tempfile::TempDir;
    use tokio::time::{Instant, sleep, timeout};
    use tokio_util::sync::CancellationToken;

    use super::{
        ConnectionRuntime, ConnectionStart, HostSession, Outbound, SessionAction, SessionInner,
        SessionOutput, SessionRequest, parse_exit, valid_handshake,
    };
    use crate::capability::{ShellKind, ShellSelection};
    use crate::config::EffectiveLimits;
    use crate::error::ErrorCode;
    use crate::ssh::SshPolicy;
    use crate::ssh::helper::HelperArtifact;

    #[test]
    fn exit_payload_is_strictly_bounded() {
        assert_eq!(parse_exit(b"7\n0\n1\n"), Ok((7, false, true, false, false)));
        assert_eq!(
            parse_exit(b"7\n0\n1\n1\n"),
            Ok((7, false, true, true, false))
        );
        assert_eq!(
            parse_exit(b"7\n0\n1\n0\n1\n"),
            Ok((7, false, true, false, true))
        );
        assert!(parse_exit(b"7\n0\n").is_err());
        assert!(parse_exit(b"7\n0\n1\nextra\n").is_err());
    }

    #[test]
    fn helper_and_shell_handshakes_are_checked_against_the_selected_transport() {
        assert!(valid_handshake(
            b"protocol=codex-ssh-helper/1;version=1;arch=x86_64;",
            Some("x86_64")
        ));
        assert!(!valid_handshake(
            b"protocol=codex-ssh-helper/1;version=1;arch=aarch64;",
            Some("x86_64")
        ));
        assert!(!valid_handshake(
            b"protocol=codex-ssh-dispatcher/1;shell=sh;",
            Some("x86_64")
        ));
        assert!(valid_handshake(
            b"protocol=codex-ssh-dispatcher/1;shell=sh;",
            None
        ));
    }

    fn limits() -> EffectiveLimits {
        EffectiveLimits {
            connect_timeout_ms: 2_000,
            command_timeout_ms: 5_000,
            max_frame_bytes: 8 * 1024 * 1024,
            read_chunk_bytes: 64 * 1024,
            max_read_bytes: 8 * 1024 * 1024,
            max_write_bytes: 8 * 1024 * 1024,
            preview_bytes: 1024,
            max_output_bytes: 8 * 1024 * 1024,
        }
    }

    fn request(command: &str, timeout: Duration) -> SessionRequest {
        SessionRequest {
            action: SessionAction::Command {
                command: command.to_owned(),
                cwd: "/tmp".to_owned(),
                shell: ShellSelection {
                    shell: ShellKind::PosixSh,
                    fallback: false,
                },
                login_shell: None,
                stdin: None,
            },
            env: BTreeMap::new(),
            timeout,
            admission_deadline: Instant::now() + timeout,
            response_timeout: timeout,
            stdout_limit: 1024,
            stderr_limit: 1024,
            output: None,
        }
    }

    fn fake_ssh(temp: &TempDir) -> PathBuf {
        let path = temp.path().join("fake-ssh");
        fs::write(
            &path,
            "#!/bin/sh\nlast=\nfor arg do last=$arg; done\nexec /bin/sh -c \"$last\"\n",
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn policy() -> SshPolicy {
        SshPolicy {
            options: Vec::new(),
            control_path: PathBuf::from("/tmp/codex-ssh-session-test-control"),
        }
    }

    #[tokio::test]
    async fn host_session_multiplexes_independent_requests_and_preserves_ids() {
        let temp = TempDir::new().unwrap();
        let session = HostSession::connect_with(
            policy(),
            "test-host".to_owned(),
            limits(),
            OsString::from(fake_ssh(&temp)),
            BTreeMap::new(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let shared = Arc::new(session);
        let first = {
            let shared = Arc::clone(&shared);
            tokio::spawn(async move {
                shared
                    .execute(
                        request("sleep 0.15; printf first", Duration::from_secs(2)),
                        CancellationToken::new(),
                    )
                    .await
                    .unwrap()
            })
        };
        let second = {
            let shared = Arc::clone(&shared);
            tokio::spawn(async move {
                shared
                    .execute(
                        request("printf second", Duration::from_secs(2)),
                        CancellationToken::new(),
                    )
                    .await
                    .unwrap()
            })
        };
        let first = first.await.unwrap();
        let second = second.await.unwrap();
        assert_ne!(first.request_id, second.request_id);
        assert_eq!(first.stdout, b"first");
        assert_eq!(second.stdout, b"second");
        shared.close().await.unwrap();
    }

    #[tokio::test]
    async fn unread_output_from_one_request_does_not_block_other_request_ids() {
        let temp = TempDir::new().unwrap();
        let mut session_limits = limits();
        session_limits.max_frame_bytes = 4096;
        let session = Arc::new(
            HostSession::connect_with(
                policy(),
                "test-host".to_owned(),
                session_limits,
                OsString::from(fake_ssh(&temp)),
                BTreeMap::new(),
                CancellationToken::new(),
            )
            .await
            .unwrap(),
        );
        let (stdout_sink, stdout_reader) = tokio::io::duplex(1);
        let (stderr_sink, stderr_reader) = tokio::io::duplex(1);
        let mut noisy_request = request(
            "dd if=/dev/zero bs=4096 count=64 2>/dev/null",
            Duration::from_secs(2),
        );
        noisy_request.stdout_limit = 256 * 1024;
        noisy_request.output = Some(SessionOutput {
            stdout: stdout_sink,
            stderr: stderr_sink,
        });
        let noisy = {
            let session = Arc::clone(&session);
            tokio::spawn(async move {
                session
                    .execute(noisy_request, CancellationToken::new())
                    .await
            })
        };

        sleep(Duration::from_millis(25)).await;
        let quick = timeout(
            Duration::from_secs(1),
            session.execute(
                request("printf quick", Duration::from_secs(1)),
                CancellationToken::new(),
            ),
        )
        .await
        .expect("an unread peer stream must not block another request ID")
        .unwrap();
        assert_eq!(quick.stdout, b"quick");
        let noisy = noisy.await.unwrap().unwrap();
        assert!(noisy.stdout_truncated);
        drop(stdout_reader);
        drop(stderr_reader);
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn host_session_cancels_one_request_without_blocking_another() {
        let temp = TempDir::new().unwrap();
        let request_start = temp.path().join("request-start");
        let environment = BTreeMap::from([
            (
                OsString::from("CODEX_SSH_BRIDGE_TEST_MODE"),
                OsString::from("1"),
            ),
            (
                OsString::from("FAKE_SSH_REQUEST_START_FILE"),
                request_start.as_os_str().to_owned(),
            ),
            (
                OsString::from("FAKE_SSH_REQUEST_START_DELAY_SECONDS"),
                OsString::from("0.05"),
            ),
        ]);
        let session = Arc::new(
            HostSession::connect_with(
                policy(),
                "test-host".to_owned(),
                limits(),
                OsString::from(fake_ssh(&temp)),
                environment,
                CancellationToken::new(),
            )
            .await
            .unwrap(),
        );
        let cancel = CancellationToken::new();
        let cancelled = {
            let session = Arc::clone(&session);
            let cancel = cancel.clone();
            tokio::spawn(async move {
                session
                    .execute(
                        request("sleep 5; printf late", Duration::from_secs(10)),
                        cancel,
                    )
                    .await
            })
        };
        timeout(Duration::from_secs(1), async {
            while !request_start.exists() {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("request did not reach the pre-PID cancellation window");
        cancel.cancel();
        let quick = timeout(
            Duration::from_secs(2),
            session.execute(
                request("printf quick", Duration::from_secs(2)),
                CancellationToken::new(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        let cancelled = cancelled.await.unwrap().unwrap_err();
        assert_eq!(cancelled.code, crate::error::ErrorCode::Cancelled);
        assert_eq!(quick.stdout, b"quick");
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn dispatcher_startup_failure_is_a_hard_error() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("failing-ssh");
        fs::write(&path, "#!/bin/sh\nexit 42\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let result = HostSession::connect_with(
            policy(),
            "test-host".to_owned(),
            limits(),
            OsString::from(path),
            BTreeMap::new(),
            CancellationToken::new(),
        )
        .await;
        let error = match result {
            Ok(_) => panic!("dispatcher startup unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(error.code, crate::error::ErrorCode::ProtocolError);
        assert!(error.message.contains("dispatcher"));
    }

    #[tokio::test]
    async fn helper_upload_backpressure_obeys_the_connection_deadline() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("blocked-ssh");
        fs::write(&path, "#!/bin/sh\nexec sleep 5\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let mut session_limits = limits();
        session_limits.connect_timeout_ms = 50;
        let connect = HostSession::connect_with_mode(
            policy(),
            "test-host".to_owned(),
            session_limits,
            CancellationToken::new(),
            ConnectionStart::Temporary {
                artifact: HelperArtifact {
                    path: temp.path().join("helper"),
                    target: "x86_64-unknown-linux-musl",
                    arch: "x86_64",
                },
                bytes: vec![0; 1024 * 1024],
            },
            ConnectionRuntime {
                executable: OsString::from(path),
                environment: BTreeMap::new(),
                deadline: Instant::now() + Duration::from_millis(50),
            },
        );
        let result = timeout(Duration::from_millis(300), connect)
            .await
            .expect("connection setup exceeded its bounded cleanup window");
        let error = match result {
            Ok(_) => panic!("blocked helper upload unexpectedly connected"),
            Err(error) => error,
        };
        assert_eq!(error.code, ErrorCode::ConnectTimeout);
    }

    #[tokio::test]
    async fn blocked_cancel_delivery_closes_the_wedged_session_within_grace() {
        let (tx, _receiver) = tokio::sync::mpsc::channel::<Outbound>(1);
        let session = HostSession {
            inner: Arc::new(SessionInner {
                host: "test-host".to_owned(),
                helper_mode: crate::ssh::HelperMode::Shell,
                max_payload: 4096,
                max_output_bytes: 4096,
                tx,
                pending: tokio::sync::Mutex::new(std::collections::HashMap::new()),
                next_id: std::sync::atomic::AtomicU64::new(1),
                closed: std::sync::atomic::AtomicBool::new(false),
                retired: std::sync::atomic::AtomicBool::new(false),
                process_group: std::sync::atomic::AtomicI32::new(0),
                writer_task: tokio::sync::Mutex::new(None),
                reader_task: tokio::sync::Mutex::new(None),
                child_task: tokio::sync::Mutex::new(None),
            }),
        };
        let started = Instant::now();
        let error = session
            .execute(
                request("printf never-delivered", Duration::from_millis(25)),
                CancellationToken::new(),
            )
            .await
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::CommandTimeout);
        assert_eq!(error.details.remote_process_may_continue, Some(true));
        assert!(session.is_closed());
        assert!(session.inner.pending.lock().await.is_empty());
        assert!(
            started.elapsed() < Duration::from_millis(400),
            "wedged writer recovery took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn accepted_cancel_without_exit_closes_the_wedged_session_within_grace() {
        let session = HostSession::wedged_for_test("test-host", 4096, 4096);
        let started = Instant::now();
        let error = session
            .execute(
                request("printf never-ready", Duration::from_millis(25)),
                CancellationToken::new(),
            )
            .await
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::CommandTimeout);
        assert_eq!(error.details.remote_process_may_continue, Some(true));
        assert!(session.is_closed());
        assert!(session.inner.pending.lock().await.is_empty());
        assert!(
            started.elapsed() < Duration::from_millis(400),
            "accepted-cancel recovery took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn dispatcher_chunks_streams_to_the_configured_frame_limit() {
        let temp = TempDir::new().unwrap();
        let mut limits = limits();
        limits.max_frame_bytes = 4096;
        let session = HostSession::connect_with(
            policy(),
            "test-host".to_owned(),
            limits,
            OsString::from(fake_ssh(&temp)),
            BTreeMap::new(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let mut request = request(
            "dd if=/dev/zero bs=4096 count=2 2>/dev/null",
            Duration::from_secs(2),
        );
        request.stdout_limit = 8192;
        request.stderr_limit = 1024;
        let result = session
            .execute(request, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(result.status, 0);
        assert_eq!(result.stdout.len(), 8192);
        assert!(!result.stdout_truncated);
        session.close().await.unwrap();
    }
}
