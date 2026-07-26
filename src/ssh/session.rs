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
use tokio::time::{Instant, timeout};
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

#[derive(Debug)]
pub(crate) struct SessionRequest {
    pub(crate) command: String,
    pub(crate) cwd: String,
    pub(crate) shell: ShellSelection,
    pub(crate) login_shell: Option<String>,
    pub(crate) env: std::collections::BTreeMap<String, Option<String>>,
    pub(crate) stdin: Option<Vec<u8>>,
    pub(crate) timeout: Duration,
    pub(crate) response_timeout: Duration,
    pub(crate) stdout_limit: u64,
    pub(crate) stderr_limit: u64,
    pub(crate) output: Option<SessionOutput>,
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
    process_group: AtomicI32,
    writer_task: Mutex<Option<JoinHandle<()>>>,
    reader_task: Mutex<Option<JoinHandle<()>>>,
    child_task: Mutex<Option<JoinHandle<()>>>,
}

struct PendingRequest {
    started: Instant,
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
        Self::connect_with_mode(
            policy,
            host,
            limits,
            executable,
            environment,
            cancel,
            ConnectionStart::Shell,
        )
        .await
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
                executable,
                environment,
                cancel,
                ConnectionStart::Shell,
            )
            .await;
        };
        let fallback_policy = policy.clone();
        let fallback_host = host.clone();
        let fallback_executable = executable.clone();
        let fallback_environment = environment.clone();
        match Self::connect_with_mode(
            policy,
            host,
            limits,
            executable,
            environment,
            cancel.clone(),
            ConnectionStart::Persistent {
                artifact: artifact.clone(),
                bytes: bytes.clone(),
                identity,
            },
        )
        .await
        {
            Ok(session) => Ok(session),
            Err(error) if helper_startup_fallback_allowed(&error, &cancel) => {
                match Self::connect_with_mode(
                    fallback_policy.clone(),
                    fallback_host.clone(),
                    limits,
                    fallback_executable.clone(),
                    fallback_environment.clone(),
                    cancel.clone(),
                    ConnectionStart::Temporary { artifact, bytes },
                )
                .await
                {
                    Ok(session) => Ok(session),
                    Err(error) if helper_startup_fallback_allowed(&error, &cancel) => {
                        Self::connect_with_mode(
                            fallback_policy,
                            fallback_host,
                            limits,
                            fallback_executable,
                            fallback_environment,
                            cancel,
                            ConnectionStart::Shell,
                        )
                        .await
                    }
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    }

    async fn connect_with_mode(
        policy: SshPolicy,
        host: String,
        limits: EffectiveLimits,
        executable: OsString,
        environment: std::collections::BTreeMap<OsString, OsString>,
        cancel: CancellationToken,
        start: ConnectionStart,
    ) -> BridgeResult<Self> {
        if limits.max_frame_bytes == 0 {
            return Err(BridgeError::invalid_argument(
                "SSH session frame limit must be positive",
            ));
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
        let mut child_command = Command::new(executable);
        child_command
            .args(argv)
            .envs(environment)
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
                        let _ = child.kill().await;
                        let _ = child.wait().await;
                        return Err(cancelled_error(&host, false));
                    }
                    result = timeout(
                        Duration::from_millis(limits.connect_timeout_ms.max(1)),
                        read_bootstrap_status_line(&mut output),
                    ) => match result {
                        Ok(Ok(status)) => status,
                        Ok(Err(error)) => {
                            let _ = child.kill().await;
                            let _ = child.wait().await;
                            return Err(error);
                        }
                        Err(_) => {
                            let _ = child.kill().await;
                            let _ = child.wait().await;
                            return Err(BridgeError::new(
                                ErrorCode::ConnectTimeout,
                                "persistent helper bootstrap timed out",
                                true,
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
                    write_helper_bytes(&mut child, &host, bytes).await?;
                    drop(helper_upload_profile);
                }
            }
            ConnectionStart::Temporary { bytes, .. } => {
                drop(helper_probe_profile);
                write_helper_bytes(&mut child, &host, bytes).await?;
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
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(cancelled_error(&host, false));
            }
            result = timeout(Duration::from_millis(limits.connect_timeout_ms.max(1)), read_frame(&mut output, limits.max_frame_bytes)) => {
                match result {
                    Ok(Ok(Some(frame))) => frame,
                    Ok(Ok(None)) => {
                        let _ = child.wait().await;
                        return Err(startup_error(&host, "SSH session closed before handshake"));
                    }
                    Ok(Err(error)) => {
                        let _ = child.kill().await;
                        let _ = child.wait().await;
                        return Err(startup_error(&host, &error.to_string()));
                    }
                    Err(_) => {
                        let _ = child.kill().await;
                        let _ = child.wait().await;
                        return Err(BridgeError::new(ErrorCode::ConnectTimeout, "SSH dispatcher handshake timed out", true));
                    }
                }
            }
        };
        drop(helper_handshake_profile);
        if hello.kind == FrameKind::Error {
            let _ = child.kill().await;
            let _ = child.wait().await;
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
            let _ = child.kill().await;
            let _ = child.wait().await;
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
        if let Err(error) = self.inner.send(Outbound { frames }).await {
            drop(helper_command_profile);
            self.inner.pending.lock().await.remove(&request_id);
            return Err(error);
        }
        drop(helper_command_profile);
        let deadline = tokio::time::sleep(request.response_timeout);
        tokio::pin!(deadline);
        tokio::select! {
            biased;
            result = &mut receiver => result.map_err(|_| transport_error(&self.inner.host, true))?,
            () = cancel.cancelled() => self.abort_request(request_id, &mut receiver, false).await,
            () = &mut deadline => self.abort_request(request_id, &mut receiver, true).await,
        }
    }

    async fn abort_request(
        &self,
        request_id: u64,
        receiver: &mut oneshot::Receiver<BridgeResult<SessionResult>>,
        timed_out: bool,
    ) -> BridgeResult<SessionResult> {
        let _ = self
            .inner
            .send(Outbound {
                frames: vec![Frame {
                    kind: FrameKind::Cancel,
                    request_id,
                    payload: Vec::new(),
                }],
            })
            .await;
        match timeout(CANCEL_GRACE, receiver).await {
            Ok(Ok(_result)) => Err(if timed_out {
                timeout_error(&self.inner.host, false)
            } else {
                cancelled_error(&self.inner.host, false)
            }),
            // Cancellation is request-scoped. A slow command teardown must not
            // close the shared transport and fail unrelated requests. Keep the
            // pending entry until its eventual EXIT (or transport failure) so
            // late frames remain protocol-valid; dropping this receiver simply
            // makes completion delivery a no-op.
            Ok(Err(_)) | Err(_) => Err(if timed_out {
                timeout_error(&self.inner.host, true)
            } else {
                cancelled_error(&self.inner.host, true)
            }),
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
}

async fn write_helper_bytes(
    child: &mut tokio::process::Child,
    host: &str,
    bytes: &[u8],
) -> BridgeResult<()> {
    let stdin = child
        .stdin
        .as_mut()
        .ok_or_else(|| BridgeError::io("SSH session stdin pipe is missing"))?;
    if let Err(error) = stdin.write_all(bytes).await {
        let _ = child.kill().await;
        let _ = child.wait().await;
        return Err(startup_error(host, &error.to_string()));
    }
    if let Err(error) = stdin.flush().await {
        let _ = child.kill().await;
        let _ = child.wait().await;
        return Err(startup_error(host, &error.to_string()));
    }
    Ok(())
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
        FrameKind::Ready => Ok(()),
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
    if request.cwd.as_bytes().contains(&0) || request.command.as_bytes().contains(&0) {
        return Err(BridgeError::invalid_argument(
            "NUL is not representable in a session cwd or command",
        ));
    }
    let cwd = request.cwd.as_bytes();
    let command = request.command.as_bytes();
    let stdin = request.stdin.as_deref().unwrap_or_default();
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
    let (shell, login_shell) = match &request.shell.shell {
        ShellKind::Bash { .. } => ("bash", ""),
        ShellKind::PosixSh => ("sh", ""),
        ShellKind::Login => {
            let login_shell = request.login_shell.as_deref().ok_or_else(|| {
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
            ErrorCode::Cancelled | ErrorCode::InvalidArgument | ErrorCode::RemoteCapabilityMissing
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
    if process_group <= 0 {
        return;
    }
    // SAFETY: kill accepts a process-group ID and does not retain pointers.
    unsafe {
        let _ = libc::kill(-process_group, libc::SIGTERM);
    }
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
    use tokio::time::{sleep, timeout};
    use tokio_util::sync::CancellationToken;

    use super::{
        ConnectionStart, HostSession, SessionOutput, SessionRequest, parse_exit, valid_handshake,
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
            command: command.to_owned(),
            cwd: "/tmp".to_owned(),
            shell: ShellSelection {
                shell: ShellKind::PosixSh,
                fallback: false,
            },
            login_shell: None,
            env: BTreeMap::new(),
            stdin: None,
            timeout,
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
        let session = Arc::new(
            HostSession::connect_with(
                policy(),
                "test-host".to_owned(),
                limits(),
                OsString::from(fake_ssh(&temp)),
                BTreeMap::new(),
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
        sleep(Duration::from_millis(50)).await;
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
            OsString::from(path),
            BTreeMap::new(),
            CancellationToken::new(),
            ConnectionStart::Temporary {
                artifact: HelperArtifact {
                    path: temp.path().join("helper"),
                    target: "x86_64-unknown-linux-musl",
                    arch: "x86_64",
                },
                bytes: vec![0; 1024 * 1024],
            },
        );
        let error = timeout(Duration::from_millis(300), connect)
            .await
            .expect("connection setup exceeded its bounded cleanup window")
            .expect_err("blocked helper upload unexpectedly connected");
        assert_eq!(error.code, ErrorCode::ConnectTimeout);
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
