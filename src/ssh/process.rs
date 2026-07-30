#![allow(
    clippy::result_large_err,
    reason = "Task 1 fixes BridgeResult<T> to an inline BridgeError representation"
)]

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::future::Future;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use std::time::SystemTime;

use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncWriteExt, duplex};
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use super::{
    HelperMode, HostSession, RuntimePaths, SessionAction, SessionOutput, SessionRequest,
    SessionResult, SshPolicy, build_ssh_argv, build_ssh_g_argv,
};
use crate::capability::{
    CAPABILITY_PROBE_SCRIPT, Capability, CapabilityCache, ShellKind, ShellRequest, ShellSelection,
    parse_probe_output, select_shell,
};
use crate::config::{Config, EffectiveLimits};
use crate::error::{
    BridgeError, BridgeResult, ErrorCode, ErrorShellMetadata, attach_available_remote_context,
};
use crate::output::{
    CaptureLimits, CapturedOutput, InternalCapturedOutput, InternalSpoolRegistration, OutputPage,
    OutputProvenance, OutputReference, OutputStore, StderrSignals, StoredProvenance, StreamKind,
};
use crate::path::RemotePath;
use crate::quote::{PreparedShellWord, shell_word};

const DEFAULT_SSH_EXECUTABLE: &str = "/usr/bin/ssh";
const RESOLVED_STDOUT_LIMIT: u64 = 1024 * 1024;
const RESOLVED_STDERR_LIMIT: u64 = 64 * 1024;
const PROBE_OUTPUT_LIMIT: u64 = 1024 * 1024;
const REMOTE_TIMEOUT_RETURN_GRACE: Duration = Duration::from_millis(200);
const TERM_GRACE: Duration = Duration::from_millis(50);
const DRAIN_GRACE: Duration = Duration::from_millis(125);
static RUNNER_INSTANCE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRequest {
    pub host: String,
    pub command: String,
    pub cwd: String,
    pub shell: ShellRequest,
    pub stdin: Option<Vec<u8>>,
    pub timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunResult {
    pub status: i32,
    pub elapsed_ms: u64,
    pub shell: ShellSelection,
    pub physical_root: String,
    pub output: CapturedOutput,
    pub remote_process_may_continue: bool,
    pub helper_mode: HelperMode,
    pub timing: RunTiming,
}

/// Internal phase timing for validating warm SSH latency. The MCP response
/// intentionally keeps the existing wire shape; callers that need timings
/// can inspect the Rust runner result directly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunTiming {
    pub preparation_ms: u64,
    pub session_ms: u64,
    pub capture_ms: u64,
    pub session_reused: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FixedOperationKind {
    ReadOnly,
    Mutation,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RootedPathInputs {
    pub(crate) argument_indices: &'static [usize],
    pub(crate) argument_stride: Option<RootedArgumentStride>,
    pub(crate) stdin_nul_paths: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RootedArgumentStride {
    pub(crate) start: usize,
    pub(crate) step: usize,
}

#[derive(Clone)]
pub(crate) struct FixedRunRequest {
    pub kind: FixedOperationKind,
    pub host: String,
    pub script: &'static str,
    pub args: Vec<String>,
    pub stdin: Option<Vec<u8>>,
    pub rooted_paths: RootedPathInputs,
    pub required_capabilities: &'static [&'static str],
    pub stdout_limit: u64,
    pub stderr_limit: u64,
    pub timeout: Duration,
    pub cleanup: InternalSpoolRegistration,
}

pub(crate) struct FixedRunResult {
    pub capability: Arc<Capability>,
    pub shell: ShellSelection,
    pub helper_mode: HelperMode,
    pub output: InternalCapturedOutput,
    pub elapsed_ms: u64,
    pub remote_process_may_continue: bool,
}

#[derive(Clone)]
pub(crate) struct NativeSearchRunRequest {
    pub host: String,
    pub root: String,
    pub query: Vec<u8>,
    pub globs: Vec<String>,
    pub max_results: usize,
    pub binary: bool,
    pub timeout: Duration,
    pub stdout_limit: u64,
}

pub(crate) struct NativeSearchRunResult {
    pub capability: Arc<Capability>,
    pub shell: ShellSelection,
    pub helper_mode: HelperMode,
    pub output: Vec<u8>,
    pub elapsed_ms: u64,
}

pub struct SshRunner {
    config: Arc<Config>,
    runtime: RuntimePaths,
    output_store: Arc<OutputStore>,
    executable: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    instance_identity: String,
    capabilities: CapabilityCache,
    policies: Mutex<HashMap<String, Arc<SshPolicy>>>,
    identities: Mutex<HashMap<String, String>>,
    initializers: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    sessions: Mutex<HashMap<String, Arc<HostSession>>>,
    session_initializers: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl SshRunner {
    pub fn new(
        config: Arc<Config>,
        runtime: RuntimePaths,
        output_store: Arc<OutputStore>,
    ) -> BridgeResult<Self> {
        Self::with_executable(
            config,
            runtime,
            output_store,
            PathBuf::from(DEFAULT_SSH_EXECUTABLE),
            BTreeMap::new(),
        )
    }

    /// Constructs a runner with a trusted local OpenSSH-compatible executable.
    ///
    /// The caller grants the executable and fixed environment local execution
    /// authority. Neither value is read from remote-host configuration.
    pub fn with_executable(
        config: Arc<Config>,
        runtime: RuntimePaths,
        output_store: Arc<OutputStore>,
        executable: PathBuf,
        environment: BTreeMap<OsString, OsString>,
    ) -> BridgeResult<Self> {
        if !executable.is_absolute() {
            return Err(BridgeError::invalid_argument(
                "SSH executable must be an absolute path",
            ));
        }
        Ok(Self {
            config,
            runtime,
            output_store,
            executable,
            environment,
            instance_identity: runner_instance_identity(),
            capabilities: CapabilityCache::default(),
            policies: Mutex::new(HashMap::new()),
            identities: Mutex::new(HashMap::new()),
            initializers: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            session_initializers: Mutex::new(HashMap::new()),
        })
    }

    pub async fn execute(
        &self,
        request: RunRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<RunResult> {
        let operation_started = Instant::now();
        let initialization_profile = crate::bridge_profile_span!(crate::profile::ProfileEvent {
            phase: "runner_initialization",
            host: Some(request.host.as_str()),
            request_id: None,
            class: None,
            elapsed_us: 0,
            bytes: None,
        });
        self.config.require_discovered_alias(&request.host)?;
        let root = crate::REMOTE_OPERATION_ROOT.to_owned();
        let limits = self.config.limits();
        validate_request(&request, limits)?;
        let setup_deadline = connect_deadline(limits.connect_timeout_ms);

        let initializer = self.initializer(&request.host).await;
        let initialize_guard = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(cancelled_error(false, 0)),
            guard = initializer.lock() => guard,
            () = tokio::time::sleep_until(setup_deadline) => {
                return Err(connect_wait_timeout(
                    &request.host,
                    "SSH host initialization wait timed out",
                ));
            }
        };
        if cancel.is_cancelled() {
            return Err(cancelled_error(false, 0));
        }

        let initialize_timeout_ms = remaining_connect_timeout_ms(setup_deadline, &request.host)?;
        let (policy, capability) = tokio::time::timeout_at(
            setup_deadline,
            self.initialize_host(&request.host, &root, initialize_timeout_ms, &cancel),
        )
        .await
        .map_err(|_| connect_wait_timeout(&request.host, "SSH host initialization timed out"))??;
        drop(initialize_guard);
        if cancel.is_cancelled() {
            return Err(cancelled_error(false, 0));
        }
        let shell = select_shell(&capability, request.shell).map_err(|mut error| {
            attach_available_remote_context(
                &mut error,
                Some(&request.host),
                Some(&capability.physical_root),
                None,
            );
            error
        })?;
        let (session, session_reused) = self
            .session_for_host(
                &policy,
                &request.host,
                limits,
                &capability,
                setup_deadline,
                &cancel,
            )
            .await
            .map_err(|error| {
                attach_selected_context(error, &request.host, &capability.physical_root, &shell)
            })?;
        let operation_deadline = Instant::now()
            .checked_add(request.timeout)
            .ok_or_else(|| BridgeError::invalid_argument("command timeout is too large"))?;
        drop(initialization_profile);
        let preparation_profile = crate::bridge_profile_span!(crate::profile::ProfileEvent {
            phase: "runner_preparation",
            host: Some(request.host.as_str()),
            request_id: None,
            class: Some(if session_reused { "warm" } else { "cold" }),
            elapsed_us: 0,
            bytes: None,
        });
        let prepared = (|| {
            let remaining = remaining_timeout(operation_deadline)?;
            let cwd = request.cwd.clone();
            let login_shell = if matches!(shell.shell, ShellKind::Login) {
                Some(capability.login_shell.clone().ok_or_else(|| {
                    BridgeError::new(
                        ErrorCode::RemoteCapabilityMissing,
                        "remote account login shell could not be resolved safely",
                        false,
                    )
                })?)
            } else {
                None
            };
            let response_timeout = remaining
                .checked_add(REMOTE_TIMEOUT_RETURN_GRACE)
                .ok_or_else(|| BridgeError::invalid_argument("command timeout is too large"))?;
            Ok((cwd, login_shell, remaining, response_timeout))
        })()
        .map_err(|error| {
            attach_selected_context(error, &request.host, &capability.physical_root, &shell)
        })?;
        let (cwd, login_shell, command_timeout, response_timeout) = prepared;
        let preparation_ms = elapsed_ms(operation_started.elapsed());
        drop(preparation_profile);
        let (stdout_writer, stdout_reader) = duplex(64 * 1024);
        let (stderr_writer, stderr_reader) = duplex(64 * 1024);
        let session_cancel = cancel.child_token();
        let capture_cancel = cancel.child_token();
        let capture = self.output_store.capture(
            stdout_reader,
            stderr_reader,
            CaptureLimits {
                preview_bytes: limits.preview_bytes,
                max_output_bytes: limits.max_output_bytes,
            },
            capture_cancel.clone(),
        );
        let capture_started = Instant::now();
        let captured = self
            .execute_with_capture(
                &session,
                SessionRequest {
                    action: SessionAction::Command {
                        command: request.command,
                        cwd,
                        shell: shell.clone(),
                        login_shell,
                        stdin: request.stdin,
                    },
                    env: BTreeMap::new(),
                    timeout: command_timeout,
                    admission_deadline: setup_deadline,
                    response_timeout,
                    stdout_limit: limits.max_output_bytes,
                    stderr_limit: limits.max_output_bytes,
                    output: Some(SessionOutput {
                        stdout: stdout_writer,
                        stderr: stderr_writer,
                    }),
                },
                capture,
                session_cancel,
                capture_cancel,
            )
            .await;
        let (session_result, output) = match captured {
            Ok(result) => result,
            Err(error) => {
                if !session.is_reusable() {
                    self.drop_session(&request.host, &session).await;
                }
                return Err(attach_selected_context(
                    error,
                    &request.host,
                    &capability.physical_root,
                    &shell,
                ));
            }
        };
        let capture_ms = elapsed_ms(capture_started.elapsed());
        let remote_process_may_continue = session_result.remote_process_may_continue;
        if session_result.timed_out {
            let mut error =
                BridgeError::new(ErrorCode::CommandTimeout, "remote command timed out", false);
            error.details.host = Some(request.host.clone());
            error.details.elapsed_ms = Some(elapsed_ms(operation_started.elapsed()));
            error.details.exit_status = Some(session_result.status);
            error.details.bytes_seen = Some(output.aggregate_bytes);
            error.details.remote_process_may_continue = Some(remote_process_may_continue);
            self.output_store.discard(&output).await;
            return Err(attach_selected_context(
                error,
                &request.host,
                &capability.physical_root,
                &shell,
            ));
        }
        if session_result.stdout_truncated || session_result.stderr_truncated {
            let mut error = BridgeError::new(
                ErrorCode::OutputLimit,
                "command output exceeded the configured limit",
                false,
            );
            error.details.host = Some(request.host.clone());
            error.details.bytes_seen = Some(output.aggregate_bytes);
            error.details.remote_process_may_continue = Some(remote_process_may_continue);
            self.output_store.discard(&output).await;
            return Err(attach_selected_context(
                error,
                &request.host,
                &capability.physical_root,
                &shell,
            ));
        }
        let status = session_result.status;
        let session_ms = session_result.elapsed_ms;
        self.output_store
            .set_provenance(
                &output,
                OutputProvenance {
                    host: request.host.clone(),
                    physical_root: capability.physical_root.clone(),
                    shell: shell.clone(),
                    helper_mode: session.helper_mode(),
                },
            )
            .await;
        Ok(RunResult {
            status,
            elapsed_ms: elapsed_ms(operation_started.elapsed()),
            shell,
            physical_root: capability.physical_root.clone(),
            output,
            remote_process_may_continue,
            helper_mode: session.helper_mode(),
            timing: RunTiming {
                preparation_ms,
                session_ms,
                capture_ms,
                session_reused,
            },
        })
    }

    pub(crate) fn config(&self) -> &Config {
        &self.config
    }

    pub(crate) async fn execute_native_search(
        &self,
        request: NativeSearchRunRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<Option<NativeSearchRunResult>> {
        self.config.require_discovered_alias(&request.host)?;
        let limits = self.config.limits();
        if request.stdout_limit == 0 || request.stdout_limit > limits.max_output_bytes {
            return Err(BridgeError::new(
                ErrorCode::RequestTooLarge,
                "native search output limit is invalid",
                false,
            ));
        }
        let setup_deadline = connect_deadline(limits.connect_timeout_ms);
        let initializer = self.initializer(&request.host).await;
        let initialize_guard = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(cancelled_error(false, 0)),
            guard = initializer.lock() => guard,
            () = tokio::time::sleep_until(setup_deadline) => {
                return Err(connect_wait_timeout(
                    &request.host,
                    "SSH host initialization wait timed out",
                ));
            }
        };
        let initialize_timeout_ms = remaining_connect_timeout_ms(setup_deadline, &request.host)?;
        let (policy, capability) = tokio::time::timeout_at(
            setup_deadline,
            self.initialize_host(
                &request.host,
                crate::REMOTE_OPERATION_ROOT,
                initialize_timeout_ms,
                &cancel,
            ),
        )
        .await
        .map_err(|_| connect_wait_timeout(&request.host, "SSH host initialization timed out"))??;
        drop(initialize_guard);
        let shell = select_shell(&capability, ShellRequest::Auto)?;
        let (session, _) = self
            .session_for_host(
                &policy,
                &request.host,
                limits,
                &capability,
                setup_deadline,
                &cancel,
            )
            .await
            .map_err(|error| {
                attach_selected_context(error, &request.host, &capability.physical_root, &shell)
            })?;
        if session.helper_mode() == HelperMode::Shell {
            return Ok(None);
        }
        let response_timeout = request
            .timeout
            .checked_add(REMOTE_TIMEOUT_RETURN_GRACE)
            .ok_or_else(|| BridgeError::invalid_argument("search timeout is too large"))?;
        let result = session
            .execute(
                SessionRequest {
                    action: SessionAction::Search {
                        root: request.root.clone(),
                        query: request.query.clone(),
                        globs: request.globs.clone(),
                        max_results: request.max_results,
                        binary: request.binary,
                    },
                    env: BTreeMap::new(),
                    timeout: request.timeout,
                    admission_deadline: setup_deadline,
                    response_timeout,
                    stdout_limit: request.stdout_limit,
                    stderr_limit: 1024,
                    output: None,
                },
                cancel,
            )
            .await
            .map_err(|error| {
                map_native_search_error(error, &request.host, &capability.physical_root, &shell)
            })?;
        if result.timed_out {
            return Err(attach_selected_context(
                BridgeError::new(ErrorCode::CommandTimeout, "remote search timed out", false),
                &request.host,
                &capability.physical_root,
                &shell,
            ));
        }
        if result.stdout_truncated || result.stderr_truncated {
            return Err(attach_selected_context(
                BridgeError::new(
                    ErrorCode::OutputLimit,
                    "remote search output exceeded the configured limit",
                    false,
                ),
                &request.host,
                &capability.physical_root,
                &shell,
            ));
        }
        if result.status != 0 {
            let mut error =
                BridgeError::new(ErrorCode::RemoteExit, "remote native search failed", false);
            error.details.exit_status = Some(result.status);
            return Err(attach_selected_context(
                error,
                &request.host,
                &capability.physical_root,
                &shell,
            ));
        }
        Ok(Some(NativeSearchRunResult {
            capability,
            shell,
            helper_mode: session.helper_mode(),
            output: result.stdout,
            elapsed_ms: result.elapsed_ms,
        }))
    }

    async fn session_for_host(
        &self,
        policy: &SshPolicy,
        host: &str,
        limits: EffectiveLimits,
        capability: &Capability,
        setup_deadline: Instant,
        cancel: &CancellationToken,
    ) -> BridgeResult<(Arc<HostSession>, bool)> {
        if let Some(session) = self.sessions.lock().await.get(host).cloned() {
            if session.is_reusable() {
                return Ok((session, true));
            }
            self.sessions.lock().await.remove(host);
        }
        let connector = {
            let mut initializers = self.session_initializers.lock().await;
            Arc::clone(
                initializers
                    .entry(host.to_owned())
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            )
        };
        let _guard = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(cancelled_error(false, 0)),
            guard = connector.lock() => guard,
            () = tokio::time::sleep_until(setup_deadline) => {
                return Err(connect_wait_timeout(
                    host,
                    "SSH session initializer wait timed out",
                ));
            }
        };
        if let Some(session) = self.sessions.lock().await.get(host).cloned() {
            if session.is_reusable() {
                return Ok((session, true));
            }
            self.sessions.lock().await.remove(host);
        }
        let connect_profile = crate::bridge_profile_span!(crate::profile::ProfileEvent {
            phase: "session_connect",
            host: Some(host),
            request_id: None,
            class: Some("cold"),
            elapsed_us: 0,
            bytes: None,
        });
        let mut connect_limits = limits;
        connect_limits.connect_timeout_ms = remaining_connect_timeout_ms(setup_deadline, host)?;
        let session = Arc::new(
            HostSession::connect_with_capability(
                policy.clone(),
                host.to_owned(),
                connect_limits,
                self.executable.clone().into_os_string(),
                self.environment.clone(),
                capability,
                cancel.clone(),
            )
            .await?,
        );
        drop(connect_profile);
        self.sessions
            .lock()
            .await
            .insert(host.to_owned(), Arc::clone(&session));
        Ok((session, false))
    }

    async fn drop_session(&self, host: &str, expected: &Arc<HostSession>) {
        let mut sessions = self.sessions.lock().await;
        if sessions
            .get(host)
            .is_some_and(|current| Arc::ptr_eq(current, expected))
        {
            sessions.remove(host);
        }
    }

    async fn execute_with_capture<T, F>(
        &self,
        session: &Arc<HostSession>,
        request: SessionRequest,
        capture: F,
        session_cancel: CancellationToken,
        capture_cancel: CancellationToken,
    ) -> BridgeResult<(SessionResult, T)>
    where
        F: Future<Output = BridgeResult<T>>,
    {
        let mut session_future = Box::pin(session.execute(request, session_cancel.clone()));
        let mut capture_future = Box::pin(capture);
        tokio::select! {
            biased;
            session_result = &mut session_future => {
                if session_result.is_err() {
                    capture_cancel.cancel();
                }
                let captured = capture_future.await;
                match (session_result, captured) {
                    (Ok(session_result), Ok(captured)) => Ok((session_result, captured)),
                    (Err(session_error), _) => Err(session_error),
                    (Ok(_), Err(capture_error)) => Err(capture_error),
                }
            }
            captured = &mut capture_future => {
                let captured = match captured {
                    Ok(captured) => captured,
                    Err(error) => {
                        session_cancel.cancel();
                        let session_result = session_future.await;
                        return match (error.code, session_result) {
                            (ErrorCode::OutputLimit, _) => Err(error),
                            (_, Err(session_error)) => Err(session_error),
                            (_, Ok(_)) => Err(error),
                        };
                    }
                };
                let session_result = session_future.await?;
                Ok((session_result, captured))
            }
        }
    }

    async fn capture_session_internal(
        &self,
        result: SessionResult,
        limits: EffectiveLimits,
        max_output_bytes: u64,
        cleanup: InternalSpoolRegistration,
        cancel: &CancellationToken,
    ) -> BridgeResult<InternalCapturedOutput> {
        let (mut stdout_writer, stdout_reader) = duplex(64 * 1024);
        let (mut stderr_writer, stderr_reader) = duplex(64 * 1024);
        let stdout = result.stdout;
        let stderr = result.stderr;
        let stdout_task = tokio::spawn(async move {
            let _ = stdout_writer.write_all(&stdout).await;
            let _ = stdout_writer.shutdown().await;
        });
        let stderr_task = tokio::spawn(async move {
            let _ = stderr_writer.write_all(&stderr).await;
            let _ = stderr_writer.shutdown().await;
        });
        let captured = self
            .output_store
            .capture_internal(
                stdout_reader,
                stderr_reader,
                CaptureLimits {
                    preview_bytes: limits.preview_bytes.max(1),
                    max_output_bytes,
                },
                cancel.clone(),
                CancellationToken::new(),
                cleanup,
            )
            .await;
        let _ = stdout_task.await;
        let _ = stderr_task.await;
        captured
    }

    pub(crate) fn fixed_command_length(
        &self,
        _host: &str,
        operation: &'static str,
        args: &[String],
    ) -> BridgeResult<usize> {
        render_fixed_command_length(operation, args)
    }

    pub(crate) async fn prepare_host(
        &self,
        host: &str,
        cancel: &CancellationToken,
    ) -> BridgeResult<(SshPolicy, Arc<Capability>)> {
        self.config.require_discovered_alias(host)?;
        let root = crate::REMOTE_OPERATION_ROOT.to_owned();
        let limits = self.config.limits();
        let initializer = self.initializer(host).await;
        let initialize_deadline = connect_deadline(limits.connect_timeout_ms);
        let initialize_guard = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(cancelled_error(false, 0)),
            guard = initializer.lock() => guard,
            () = tokio::time::sleep_until(initialize_deadline) => {
                return Err(connect_wait_timeout(
                    host,
                    "SSH host initialization wait timed out",
                ));
            }
        };
        let initialize_timeout_ms = remaining_connect_timeout_ms(initialize_deadline, host)?;
        let prepared = tokio::time::timeout_at(
            initialize_deadline,
            self.initialize_host(host, &root, initialize_timeout_ms, cancel),
        )
        .await
        .map_err(|_| connect_wait_timeout(host, "SSH host initialization timed out"))?;
        drop(initialize_guard);
        prepared
    }

    pub(crate) async fn cached_capability(&self, host: &str) -> Option<Arc<Capability>> {
        self.capabilities.get(host).await
    }

    pub(crate) async fn invalidate_capability(&self, host: &str) -> bool {
        self.capabilities.invalidate(host).await
    }

    pub(crate) async fn read_output(
        &self,
        reference: &OutputReference,
        stream: StreamKind,
        offset: u64,
        max_bytes: usize,
    ) -> BridgeResult<OutputPage> {
        self.output_store
            .read(reference, stream, offset, max_bytes)
            .await
    }

    pub(crate) async fn output_provenance(
        &self,
        reference: &OutputReference,
    ) -> BridgeResult<StoredProvenance> {
        self.output_store.provenance(reference).await
    }

    pub(crate) async fn retain_serialized_detail<T: Serialize + Send + 'static>(
        &self,
        provenance: StoredProvenance,
        owned: T,
        cancel: CancellationToken,
    ) -> BridgeResult<OutputReference> {
        self.output_store
            .retain_serialized_detail(provenance, owned, cancel)
            .await
    }

    pub(crate) async fn retain_bytes(
        &self,
        provenance: StoredProvenance,
        owned: Vec<u8>,
        cancel: CancellationToken,
    ) -> BridgeResult<OutputReference> {
        self.output_store
            .retain_bytes(provenance, owned, cancel)
            .await
    }

    pub(crate) async fn execute_fixed_once(
        &self,
        mut request: FixedRunRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<FixedRunResult> {
        self.config.require_discovered_alias(&request.host)?;
        let limits = self.config.limits();
        let root = crate::REMOTE_OPERATION_ROOT.to_owned();
        let setup_deadline = connect_deadline(limits.connect_timeout_ms);
        if request.timeout.is_zero()
            || request.timeout > Duration::from_millis(limits.command_timeout_ms)
        {
            return Err(BridgeError::invalid_argument(
                "fixed command timeout is outside the configured limit",
            ));
        }
        let transport_bytes = render_fixed_command_length(request.script, &request.args)?
            .checked_add(request.stdin.as_ref().map_or(0, Vec::len))
            .ok_or_else(|| {
                BridgeError::new(
                    ErrorCode::RequestTooLarge,
                    "fixed request exceeds the configured frame limit",
                    false,
                )
            })?;
        if transport_bytes > limits.max_frame_bytes
            || request.stdout_limit == 0
            || request.stderr_limit == 0
        {
            return Err(BridgeError::new(
                ErrorCode::RequestTooLarge,
                "fixed request exceeds the configured frame limit",
                false,
            ));
        }
        let capture_limit = request
            .stdout_limit
            .checked_add(request.stderr_limit)
            .ok_or_else(|| {
                BridgeError::new(
                    ErrorCode::RequestTooLarge,
                    "fixed output limit overflowed",
                    false,
                )
            })?;
        if capture_limit > limits.max_output_bytes {
            return Err(BridgeError::new(
                ErrorCode::RequestTooLarge,
                "fixed output exceeds the configured limit",
                false,
            ));
        }

        let initializer = self.initializer(&request.host).await;
        let initialize_guard = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(cancelled_error(false, 0)),
            guard = initializer.lock() => guard,
            () = tokio::time::sleep_until(setup_deadline) => {
                return Err(connect_wait_timeout(
                    &request.host,
                    "SSH host initialization wait timed out",
                ));
            }
        };
        let initialize_timeout_ms = remaining_connect_timeout_ms(setup_deadline, &request.host)?;
        let (policy, capability) = tokio::time::timeout_at(
            setup_deadline,
            self.initialize_host(&request.host, &root, initialize_timeout_ms, &cancel),
        )
        .await
        .map_err(|_| connect_wait_timeout(&request.host, "SSH host initialization timed out"))??;
        drop(initialize_guard);
        let shell = ShellSelection {
            shell: ShellKind::PosixSh,
            fallback: false,
        };
        for key in request.required_capabilities {
            if capability.tools.get(*key) != Some(&true) {
                return Err(attach_selected_context(
                    BridgeError::new(
                        ErrorCode::RemoteCapabilityMissing,
                        format!("remote host lacks required capability: {key}"),
                        false,
                    ),
                    &request.host,
                    &capability.physical_root,
                    &shell,
                ));
            }
        }
        let (session, _session_reused) = self
            .session_for_host(
                &policy,
                &request.host,
                limits,
                &capability,
                setup_deadline,
                &cancel,
            )
            .await
            .map_err(|error| {
                attach_selected_context(error, &request.host, &capability.physical_root, &shell)
            })?;
        let operation_deadline = Instant::now()
            .checked_add(request.timeout)
            .ok_or_else(|| BridgeError::invalid_argument("fixed command timeout is too large"))?;
        pin_fixed_inputs(
            &root,
            &mut request.args,
            request.stdin.as_mut(),
            request.rooted_paths,
        )?;
        let stdin_bytes = request.stdin.as_ref().map_or(0, Vec::len);
        let command_limit = limits
            .max_frame_bytes
            .checked_sub(stdin_bytes)
            .ok_or_else(rendered_too_large)?;
        let remote_command =
            render_fixed_command_text(request.script, &request.args, command_limit)?;
        let command_timeout = remaining_timeout(operation_deadline).map_err(|error| {
            attach_selected_context(error, &request.host, &capability.physical_root, &shell)
        })?;
        let response_timeout = command_timeout
            .checked_add(REMOTE_TIMEOUT_RETURN_GRACE)
            .ok_or_else(|| BridgeError::invalid_argument("fixed command timeout is too large"))?;
        let session_result = match session
            .execute(
                SessionRequest {
                    action: SessionAction::Command {
                        command: remote_command,
                        cwd: root.clone(),
                        shell: shell.clone(),
                        login_shell: None,
                        stdin: request.stdin,
                    },
                    env: BTreeMap::new(),
                    timeout: command_timeout,
                    admission_deadline: setup_deadline,
                    response_timeout,
                    stdout_limit: request.stdout_limit,
                    stderr_limit: request.stderr_limit,
                    output: None,
                },
                cancel.clone(),
            )
            .await
        {
            Ok(result) => result,
            Err(error) => {
                if !session.is_reusable() {
                    self.drop_session(&request.host, &session).await;
                }
                return Err(attach_selected_context(
                    request.kind.after_spawn_error(error),
                    &request.host,
                    &capability.physical_root,
                    &shell,
                ));
            }
        };
        if session_result.status != 0 {
            let mut error = BridgeError::new(
                ErrorCode::RemoteExit,
                "remote fixed operation failed",
                false,
            );
            error.details.exit_status = Some(session_result.status);
            error.details.host = Some(request.host.clone());
            return Err(attach_selected_context(
                request.kind.after_spawn_error(error),
                &request.host,
                &capability.physical_root,
                &shell,
            ));
        }
        if session_result.stdout_truncated || session_result.stderr_truncated {
            let mut error = BridgeError::new(
                ErrorCode::OutputLimit,
                "fixed output exceeded its stream limit",
                false,
            );
            error.details.elapsed_ms = Some(session_result.elapsed_ms);
            error.details.bytes_seen = Some(
                u64::try_from(session_result.stdout.len())
                    .unwrap_or(u64::MAX)
                    .saturating_add(u64::try_from(session_result.stderr.len()).unwrap_or(u64::MAX)),
            );
            error.details.remote_process_may_continue = Some(true);
            return Err(attach_selected_context(
                request.kind.after_spawn_error(error),
                &request.host,
                &capability.physical_root,
                &shell,
            ));
        }
        let session_elapsed_ms = session_result.elapsed_ms;
        let session_remote_process_may_continue = session_result.remote_process_may_continue;
        let output = self
            .capture_session_internal(
                session_result,
                limits,
                capture_limit,
                request.cleanup,
                &cancel,
            )
            .await
            .map_err(|error| request.kind.after_spawn_error(error))
            .map_err(|error| {
                attach_selected_context(error, &request.host, &capability.physical_root, &shell)
            })?;
        if output.stdout_len > request.stdout_limit || output.stderr_len > request.stderr_limit {
            return Err(attach_selected_context(
                request.kind.after_spawn_error(BridgeError::new(
                    ErrorCode::OutputLimit,
                    "fixed output exceeded its stream limit",
                    false,
                )),
                &request.host,
                &capability.physical_root,
                &shell,
            ));
        }
        Ok(FixedRunResult {
            capability,
            shell,
            helper_mode: session.helper_mode(),
            output,
            elapsed_ms: session_elapsed_ms,
            remote_process_may_continue: session_remote_process_may_continue,
        })
    }

    async fn initializer(&self, host: &str) -> Arc<Mutex<()>> {
        let mut initializers = self.initializers.lock().await;
        Arc::clone(
            initializers
                .entry(host.to_owned())
                .or_insert_with(|| Arc::new(Mutex::new(()))),
        )
    }

    async fn initialize_host(
        &self,
        host: &str,
        root: &str,
        connect_timeout_ms: u64,
        cancel: &CancellationToken,
    ) -> BridgeResult<(SshPolicy, Arc<Capability>)> {
        let cached_policy = self.policies.lock().await.get(host).cloned();
        let policy = match cached_policy {
            Some(policy) => (*policy).clone(),
            None => {
                let resolved_identity = self
                    .resolve_identity_once(host, connect_timeout_ms, cancel)
                    .await?;
                let identity = {
                    let mut identities = self.identities.lock().await;
                    match identities.get(host) {
                        Some(identity) if identity != &resolved_identity => {
                            return Err(BridgeError::invalid_config(
                                "resolved SSH connection identity changed; verify the alias and restart the bridge",
                            ));
                        }
                        Some(identity) => identity.clone(),
                        None => {
                            identities.insert(host.to_owned(), resolved_identity.clone());
                            resolved_identity
                        }
                    }
                };
                let policy = SshPolicy::for_host_with_instance(
                    host,
                    self.config.limits(),
                    &self.runtime,
                    &identity,
                    &self.instance_identity,
                )?;
                self.policies
                    .lock()
                    .await
                    .insert(host.to_owned(), Arc::new(policy.clone()));
                policy
            }
        };
        let capability = self
            .capabilities
            .get_or_probe(host, || async {
                self.probe_capability(&policy, host, root, connect_timeout_ms, cancel)
                    .await
            })
            .await?;
        Ok((policy, capability))
    }

    async fn resolve_identity_once(
        &self,
        host: &str,
        connect_timeout_ms: u64,
        cancel: &CancellationToken,
    ) -> BridgeResult<String> {
        let argv = build_ssh_g_argv(host, self.config.limits().connect_timeout_ms);
        let total_limit = RESOLVED_STDOUT_LIMIT + RESOLVED_STDERR_LIMIT;
        let outcome = self
            .run_child(
                ChildSpec {
                    argv,
                    stdin: None,
                    capture_limits: CaptureLimits {
                        preview_bytes: usize::try_from(total_limit * 2)
                            .expect("resolved output bound fits usize"),
                        max_output_bytes: total_limit,
                    },
                    deadline: Duration::from_millis(connect_timeout_ms),
                    phase: Phase::Resolve,
                    internal_registration: None,
                },
                cancel,
                host,
            )
            .await
            .map_err(|error| {
                if error.code == ErrorCode::OutputLimit
                    && error.message == "command output exceeded the configured limit"
                {
                    BridgeError::new(
                        ErrorCode::ProtocolError,
                        "resolved SSH configuration exceeded its output limit",
                        false,
                    )
                } else {
                    error
                }
            })?;
        let output = outcome.output.into_public()?;
        if output.stdout.bytes_seen > RESOLVED_STDOUT_LIMIT
            || output.stderr.bytes_seen > RESOLVED_STDERR_LIMIT
        {
            self.output_store.discard(&output).await;
            return Err(BridgeError::new(
                ErrorCode::ProtocolError,
                "resolved SSH configuration exceeded its stream limit",
                false,
            ));
        }
        let stdout = joined_preview(&output.stdout);
        self.output_store.discard(&output).await;
        let digest = Sha256::digest(stdout);
        Ok(hex_digest(&digest))
    }

    async fn probe_capability(
        &self,
        policy: &SshPolicy,
        host: &str,
        root: &str,
        connect_timeout_ms: u64,
        cancel: &CancellationToken,
    ) -> BridgeResult<Capability> {
        let requested_root = RemotePath::resolve(root, ".")?;
        let remote_command = capability_probe_command(root)?;
        let outcome = self
            .run_child(
                ChildSpec {
                    argv: build_ssh_argv(policy, host, &remote_command),
                    stdin: None,
                    capture_limits: CaptureLimits {
                        preview_bytes: usize::try_from(PROBE_OUTPUT_LIMIT * 2)
                            .expect("probe output bound fits usize"),
                        max_output_bytes: PROBE_OUTPUT_LIMIT,
                    },
                    deadline: Duration::from_millis(connect_timeout_ms),
                    phase: Phase::Probe,
                    internal_registration: None,
                },
                cancel,
                host,
            )
            .await
            .map_err(|error| {
                if error.code == ErrorCode::RemoteExit && error.details.exit_status == Some(78) {
                    BridgeError::new(
                        ErrorCode::RemoteCapabilityMissing,
                        "remote root identity requires compatible GNU or BSD stat",
                        false,
                    )
                } else {
                    error
                }
            })?;
        let output = outcome.output.into_public()?;
        let stdout = joined_preview(&output.stdout);
        let parsed = parse_probe_output(&stdout, &requested_root);
        self.output_store.discard(&output).await;
        parsed
    }

    async fn run_child(
        &self,
        spec: ChildSpec,
        cancel: &CancellationToken,
        host: &str,
    ) -> BridgeResult<ChildOutcome> {
        if cancel.is_cancelled() {
            return Err(cancelled_error(false, 0));
        }
        let started = Instant::now();
        let mut command = Command::new(&self.executable);
        command
            .args(spec.argv)
            .envs(&self.environment)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        command.env("LC_ALL", "C");
        // SAFETY: pre_exec runs in the child after fork and calls only setpgid,
        // an async-signal-safe libc function. It captures no parent references.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        let mut child = command.spawn().map_err(BridgeError::io)?;
        // From this point the mutation outcome is ambiguous. These setup
        // checks run before any internal spool exists; on an early return the
        // still-owned child is killed by `kill_on_drop`.
        let process_group = child
            .id()
            .ok_or_else(|| BridgeError::new(ErrorCode::Io, "SSH child has no process id", false))
            .map_err(|error| spec.phase.after_spawn_error(error))?
            as i32;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| BridgeError::new(ErrorCode::Io, "SSH stdout pipe is missing", false))
            .map_err(|error| spec.phase.after_spawn_error(error))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| BridgeError::new(ErrorCode::Io, "SSH stderr pipe is missing", false))
            .map_err(|error| spec.phase.after_spawn_error(error))?;
        let child_stdin = child.stdin.take();
        let mut stdin_task = tokio::spawn(write_stdin(
            child_stdin,
            spec.stdin,
            spec.phase.accepts_early_stdin_close(),
        ));
        let output_limit = CancellationToken::new();
        let mut capture_task = {
            let store = Arc::clone(&self.output_store);
            let output_limit_signal = output_limit.clone();
            let capture_cancel = cancel.clone();
            tokio::spawn(async move {
                match spec.internal_registration.clone() {
                    Some(registration) => store
                        .capture_internal(
                            stdout,
                            stderr,
                            spec.capture_limits,
                            capture_cancel,
                            output_limit_signal,
                            registration,
                        )
                        .await
                        .map(ChildCaptured::Internal),
                    None => store
                        .capture_with_limit_signal(
                            stdout,
                            stderr,
                            spec.capture_limits,
                            capture_cancel,
                            output_limit_signal,
                        )
                        .await
                        .map(ChildCaptured::Public),
                }
            })
        };
        let mut wait_task = tokio::spawn(async move { child.wait().await });
        let mut status = None;
        let mut capture = None;
        let mut stdin_finished = false;
        let deadline = tokio::time::sleep(spec.deadline);
        tokio::pin!(deadline);

        let stop = loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => break Stop::Cancelled,
                () = output_limit.cancelled() => break Stop::OutputLimit,
                () = &mut deadline => break Stop::Deadline,
                result = &mut wait_task, if status.is_none() => {
                    match joined_wait(result) {
                        Ok(exit_status) => status = Some(exit_status),
                        Err(error) => break Stop::InternalError(Box::new(error)),
                    }
                    if capture.is_some() && stdin_finished {
                        break Stop::Completed;
                    }
                }
                result = &mut capture_task, if capture.is_none() => {
                    let result = joined_capture(result);
                    let stop_for_error = match &result {
                        Err(error) if error.code == ErrorCode::OutputLimit => {
                            Some(Stop::OutputLimit)
                        }
                        Err(error) => Some(Stop::InternalError(Box::new(error.clone()))),
                        Ok(_) => None,
                    };
                    capture = Some(result);
                    if let Some(stop) = stop_for_error {
                        break stop;
                    }
                    if status.is_some() && stdin_finished {
                        break Stop::Completed;
                    }
                }
                result = &mut stdin_task, if !stdin_finished => {
                    stdin_finished = true;
                    if let Err(error) = joined_stdin(result) {
                        break Stop::InternalError(Box::new(error));
                    }
                    if status.is_some() && capture.is_some() {
                        break Stop::Completed;
                    }
                }
            }
        };

        match stop {
            Stop::Completed => {
                let status = status.expect("completed child status");
                let output = capture.expect("completed capture")?;
                self.classify_exit(status, output, spec.phase, host, started.elapsed())
                    .await
            }
            Stop::Cancelled | Stop::OutputLimit | Stop::Deadline | Stop::InternalError(_) => {
                terminate_process_group(process_group).await;
                if status.is_none() {
                    let _ = finish_wait(wait_task).await;
                }
                // stdin and capture share one drain-grace window so forced
                // return remains inside the 250 ms acceptance budget.
                let stdin_finish = async move {
                    if !stdin_finished {
                        let _ = finish_stdin_bounded(stdin_task).await;
                    }
                };
                let capture_finish = async move {
                    match capture {
                        Some(capture) => capture,
                        None => finish_capture_bounded(capture_task).await,
                    }
                };
                let (_, capture) = tokio::join!(stdin_finish, capture_finish);
                let bytes_seen = capture
                    .as_ref()
                    .ok()
                    .map(ChildCaptured::aggregate_bytes)
                    .or_else(|| {
                        capture
                            .as_ref()
                            .err()
                            .and_then(|error| error.details.bytes_seen)
                    })
                    .unwrap_or(0);
                if let Ok(ChildCaptured::Public(output)) = &capture {
                    self.output_store.discard(output).await;
                }
                let stopped_for_output_limit = matches!(&stop, Stop::OutputLimit);
                let mut error = match stop {
                    Stop::Cancelled => cancelled_error(spec.phase.remote_started(), bytes_seen),
                    Stop::Deadline => spec.phase.timeout_error(bytes_seen),
                    Stop::OutputLimit => match capture {
                        Err(error) if error.code == ErrorCode::OutputLimit => error,
                        _ => BridgeError::new(
                            ErrorCode::OutputLimit,
                            "command output exceeded the configured limit",
                            false,
                        ),
                    },
                    Stop::InternalError(error) => *error,
                    Stop::Completed => unreachable!(),
                };
                error.details.host = Some(host.to_owned());
                error.details.elapsed_ms = Some(elapsed_ms(started.elapsed()));
                if stopped_for_output_limit {
                    error.details.bytes_seen = Some(bytes_seen);
                    error.details.remote_process_may_continue = Some(spec.phase.remote_started());
                }
                Err(spec.phase.after_spawn_error(error))
            }
        }
    }

    async fn classify_exit(
        &self,
        status: ExitStatus,
        output: ChildCaptured,
        phase: Phase,
        host: &str,
        elapsed: Duration,
    ) -> BridgeResult<ChildOutcome> {
        let Some(code) = status.code() else {
            return self.failed_exit(-1, output, phase, host, elapsed).await;
        };
        if code == 0 {
            return Ok(ChildOutcome { output });
        }
        self.failed_exit(code, output, phase, host, elapsed).await
    }

    async fn failed_exit(
        &self,
        code: i32,
        output: ChildCaptured,
        phase: Phase,
        host: &str,
        elapsed: Duration,
    ) -> BridgeResult<ChildOutcome> {
        let error_code = if code == 255 && phase.allows_transport_classification() {
            classify_ssh_255(output.stderr_signals())
        } else {
            ErrorCode::RemoteExit
        };
        let retryable = error_code == ErrorCode::ConnectTimeout;
        let message = match error_code {
            ErrorCode::HostKeyUnknown => "SSH host key is unknown or changed",
            ErrorCode::AuthRequired => "SSH authentication is required",
            ErrorCode::ConnectTimeout => "SSH connection timed out",
            ErrorCode::CommandTimeout => "remote command timed out",
            ErrorCode::RemoteExit => "remote command exited unsuccessfully",
            _ => "SSH operation failed",
        };
        let mut error = BridgeError::new(error_code, message, retryable);
        error.details.host = Some(host.to_owned());
        error.details.elapsed_ms = Some(elapsed_ms(elapsed));
        error.details.exit_status = Some(code);
        error.details.bytes_seen = Some(output.aggregate_bytes());
        if let ChildCaptured::Public(output) = &output {
            self.output_store.discard(output).await;
        }
        Err(phase.after_spawn_error(error))
    }
}

struct ChildOutcome {
    output: ChildCaptured,
}

enum ChildCaptured {
    Public(CapturedOutput),
    Internal(InternalCapturedOutput),
}

fn mutation_unknown(mut source: BridgeError) -> BridgeError {
    let mut error = BridgeError::mutation_outcome_unknown();
    error.details.host = source.details.host.take();
    error.details.physical_root = source.details.physical_root.take();
    error.details.shell = source.details.shell.take();
    error.details.elapsed_ms = source.details.elapsed_ms;
    error.details.exit_status = source.details.exit_status;
    error.details.bytes_seen = source.details.bytes_seen;
    error.details.remote_process_may_continue = source.details.remote_process_may_continue;
    error
}

fn error_shell_metadata(shell: &ShellSelection) -> ErrorShellMetadata {
    let (kind, version) = match &shell.shell {
        ShellKind::Bash { version } => ("bash", Some(version.clone())),
        ShellKind::PosixSh => ("sh", None),
        ShellKind::Login => ("login", None),
    };
    ErrorShellMetadata {
        kind: kind.to_owned(),
        version,
        fallback: shell.fallback,
    }
}

fn attach_selected_context(
    mut error: BridgeError,
    host: &str,
    physical_root: &str,
    shell: &ShellSelection,
) -> BridgeError {
    let shell = error_shell_metadata(shell);
    attach_available_remote_context(&mut error, Some(host), Some(physical_root), Some(&shell));
    error
}

fn map_native_search_error(
    error: BridgeError,
    host: &str,
    physical_root: &str,
    shell: &ShellSelection,
) -> BridgeError {
    let mapped = match error.message.as_str() {
        "search-root-not-found" => BridgeError::new(ErrorCode::NotFound, "path not found", false),
        "search-root-not-directory" => {
            BridgeError::new(ErrorCode::NotDirectory, "path is not a directory", false)
        }
        "search-root-permission-denied"
        | "search-directory-read-failed"
        | "search-file-permission-denied" => {
            BridgeError::new(ErrorCode::PermissionDenied, "permission denied", false)
        }
        _ => error,
    };
    attach_selected_context(mapped, host, physical_root, shell)
}

impl FixedOperationKind {
    fn after_spawn_error(self, error: BridgeError) -> BridgeError {
        match self {
            Self::ReadOnly => error,
            Self::Mutation => mutation_unknown(error),
        }
    }
}

impl ChildCaptured {
    fn aggregate_bytes(&self) -> u64 {
        match self {
            Self::Public(output) => output.aggregate_bytes,
            Self::Internal(output) => output.aggregate_bytes,
        }
    }
    fn stderr_signals(&self) -> StderrSignals {
        match self {
            Self::Public(output) => output.stderr_signals,
            Self::Internal(_) => StderrSignals::default(),
        }
    }
    fn into_public(self) -> BridgeResult<CapturedOutput> {
        match self {
            Self::Public(output) => Ok(output),
            Self::Internal(_) => Err(BridgeError::new(
                ErrorCode::Io,
                "internal capture used by public command",
                false,
            )),
        }
    }
}

struct ChildSpec {
    argv: Vec<OsString>,
    stdin: Option<Vec<u8>>,
    capture_limits: CaptureLimits,
    deadline: Duration,
    phase: Phase,
    internal_registration: Option<InternalSpoolRegistration>,
}

#[derive(Clone, Copy)]
#[allow(dead_code)]
enum Phase {
    Resolve,
    Probe,
    Fixed { kind: FixedOperationKind },
}

impl Phase {
    fn remote_started(self) -> bool {
        !matches!(self, Self::Resolve)
    }

    fn after_spawn_error(self, error: BridgeError) -> BridgeError {
        match self {
            Self::Fixed { kind } => kind.after_spawn_error(error),
            Self::Resolve | Self::Probe => error,
        }
    }

    fn allows_transport_classification(self) -> bool {
        matches!(self, Self::Resolve | Self::Probe)
    }

    fn accepts_early_stdin_close(self) -> bool {
        matches!(
            self,
            Self::Fixed {
                kind: FixedOperationKind::Mutation
            }
        )
    }

    fn timeout_error(self, bytes_seen: u64) -> BridgeError {
        let (code, message, retryable) = match self {
            Self::Resolve => (
                ErrorCode::ConnectTimeout,
                "SSH configuration timed out",
                true,
            ),
            Self::Probe => (
                ErrorCode::ConnectTimeout,
                "SSH capability probe timed out",
                true,
            ),
            Self::Fixed { .. } => (ErrorCode::CommandTimeout, "remote command timed out", false),
        };
        let mut error = BridgeError::new(code, message, retryable);
        error.details.remote_process_may_continue = Some(self.remote_started());
        error.details.bytes_seen = Some(bytes_seen);
        error
    }
}

enum Stop {
    Completed,
    Cancelled,
    OutputLimit,
    Deadline,
    InternalError(Box<BridgeError>),
}

fn remaining_timeout(deadline: Instant) -> BridgeResult<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| {
            let mut error = BridgeError::new(
                ErrorCode::CommandTimeout,
                "remote operation exhausted its timeout before command completion",
                false,
            );
            error.details.remote_process_may_continue = Some(false);
            error
        })
}

fn connect_deadline(connect_timeout_ms: u64) -> Instant {
    Instant::now() + Duration::from_millis(connect_timeout_ms.max(1))
}

fn remaining_connect_timeout_ms(deadline: Instant, host: &str) -> BridgeResult<u64> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| connect_wait_timeout(host, "SSH connection setup timed out"))?;
    Ok(u64::try_from(remaining.as_millis())
        .unwrap_or(u64::MAX)
        .max(1))
}

fn connect_wait_timeout(host: &str, message: &str) -> BridgeError {
    let mut error = BridgeError::new(ErrorCode::ConnectTimeout, message, true);
    error.details.host = Some(host.to_owned());
    error.details.remote_process_may_continue = Some(false);
    error
}

fn runner_instance_identity() -> String {
    let sequence = RUNNER_INSTANCE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let unix_nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}:{unix_nanos}:{sequence}", std::process::id())
}

fn validate_request(request: &RunRequest, limits: EffectiveLimits) -> BridgeResult<()> {
    let timeout_ms = request.timeout.as_millis();
    if timeout_ms == 0 || timeout_ms > u128::from(limits.command_timeout_ms) {
        return Err(BridgeError::invalid_argument(format!(
            "command timeout must be between 1 and {} milliseconds",
            limits.command_timeout_ms
        )));
    }
    if request.command.as_bytes().contains(&0) || request.cwd.as_bytes().contains(&0) {
        return Err(BridgeError::invalid_argument(
            "NUL is not representable in a remote command or cwd",
        ));
    }
    if request
        .stdin
        .as_ref()
        .is_some_and(|stdin| stdin.len() > limits.max_write_bytes)
    {
        return Err(BridgeError::new(
            ErrorCode::RequestTooLarge,
            "command input exceeds the configured limit",
            false,
        ));
    }
    Ok(())
}

fn checked_rendered_length(lengths: impl IntoIterator<Item = usize>) -> BridgeResult<usize> {
    lengths.into_iter().try_fold(0usize, |total, length| {
        total.checked_add(length).ok_or_else(rendered_too_large)
    })
}

fn ensure_rendered_bound(length: usize, maximum: usize) -> BridgeResult<()> {
    if length > maximum {
        return Err(rendered_too_large());
    }
    Ok(())
}

fn rendered_too_large() -> BridgeError {
    BridgeError::new(
        ErrorCode::RequestTooLarge,
        "rendered command exceeds the configured frame limit",
        false,
    )
}

pub(crate) fn render_fixed_command(script: &'static str, args: &[String]) -> BridgeResult<String> {
    render_fixed_command_text(script, args, usize::MAX)
}

fn render_fixed_command_length(script: &str, args: &[String]) -> BridgeResult<usize> {
    let script = PreparedShellWord::new(script)?;
    args.iter().try_fold(
        checked_rendered_length([
            FIXED_COMMAND_PREFIX.len(),
            script.len(),
            FIXED_COMMAND_ARG0.len(),
        ])?,
        |length, argument| {
            let argument = PreparedShellWord::new(argument)?;
            checked_rendered_length([length, 1, argument.len()])
        },
    )
}

const FIXED_COMMAND_PREFIX: &str = "exec sh -c ";
const FIXED_COMMAND_ARG0: &str = " codex-ssh-bridge-op";

fn render_fixed_command_text(
    script: &str,
    args: &[String],
    maximum: usize,
) -> BridgeResult<String> {
    let script = PreparedShellWord::new(script)?;
    let args = args
        .iter()
        .map(|argument| PreparedShellWord::new(argument))
        .collect::<BridgeResult<Vec<_>>>()?;
    let length = args.iter().try_fold(
        checked_rendered_length([
            FIXED_COMMAND_PREFIX.len(),
            script.len(),
            FIXED_COMMAND_ARG0.len(),
        ])?,
        |length, argument| checked_rendered_length([length, 1, argument.len()]),
    )?;
    ensure_rendered_bound(length, maximum)?;
    let mut command = String::with_capacity(length);
    command.push_str(FIXED_COMMAND_PREFIX);
    script.push_to(&mut command)?;
    command.push_str(FIXED_COMMAND_ARG0);
    for argument in args {
        command.push(' ');
        argument.push_to(&mut command)?;
    }
    debug_assert_eq!(command.len(), length);
    Ok(command)
}

fn pin_fixed_inputs(
    configured_root: &str,
    args: &mut [String],
    stdin: Option<&mut Vec<u8>>,
    rooted: RootedPathInputs,
) -> BridgeResult<()> {
    let configured = RemotePath::resolve(configured_root, ".")?;
    for index in rooted.argument_indices {
        let argument = args.get_mut(*index).ok_or_else(|| {
            BridgeError::new(
                ErrorCode::ProtocolError,
                "fixed rooted argument index is invalid",
                false,
            )
        })?;
        *argument = root_relative_one(configured.as_str(), argument)?;
    }
    if let Some(stride) = rooted.argument_stride {
        if stride.step == 0 || stride.start >= args.len() {
            return Err(BridgeError::new(
                ErrorCode::ProtocolError,
                "fixed rooted argument stride is invalid",
                false,
            ));
        }
        for argument in args.iter_mut().skip(stride.start).step_by(stride.step) {
            *argument = root_relative_one(configured.as_str(), argument)?;
        }
    }
    if rooted.stdin_nul_paths {
        let stdin = stdin.ok_or_else(|| {
            BridgeError::new(
                ErrorCode::ProtocolError,
                "fixed rooted stdin is missing",
                false,
            )
        })?;
        if stdin.last() != Some(&0) {
            return Err(BridgeError::new(
                ErrorCode::ProtocolError,
                "fixed rooted stdin is not NUL terminated",
                false,
            ));
        }
        let mut rewritten = Vec::with_capacity(stdin.len());
        for field in stdin[..stdin.len() - 1].split(|byte| *byte == 0) {
            rewritten
                .extend_from_slice(&root_relative_bytes(configured.as_str().as_bytes(), field)?);
            rewritten.push(0);
        }
        *stdin = rewritten;
    }
    Ok(())
}

fn root_relative_one(configured_root: &str, path: &str) -> BridgeResult<String> {
    String::from_utf8(root_relative_bytes(
        configured_root.as_bytes(),
        path.as_bytes(),
    )?)
    .map_err(|_| rooted_path_error())
}

fn root_relative_bytes(configured_root: &[u8], path: &[u8]) -> BridgeResult<Vec<u8>> {
    let relative = if path == configured_root {
        b"".as_slice()
    } else if configured_root == b"/" {
        path.strip_prefix(b"/").ok_or_else(rooted_path_error)?
    } else {
        path.strip_prefix(configured_root)
            .and_then(|suffix| suffix.strip_prefix(b"/"))
            .ok_or_else(rooted_path_error)?
    };
    if relative.is_empty() {
        Ok(b".".to_vec())
    } else {
        let mut pinned = Vec::with_capacity(relative.len() + 2);
        pinned.extend_from_slice(b"./");
        pinned.extend_from_slice(relative);
        Ok(pinned)
    }
}

fn rooted_path_error() -> BridgeError {
    BridgeError::new(
        ErrorCode::ProtocolError,
        "fixed rooted path escaped the configured root",
        false,
    )
}

fn capability_probe_command(root: &str) -> BridgeResult<String> {
    Ok(format!(
        "exec sh -c {} codex-ssh-probe {}",
        shell_word(CAPABILITY_PROBE_SCRIPT)?,
        shell_word(root)?
    ))
}

async fn write_stdin(
    mut stdin: Option<tokio::process::ChildStdin>,
    bytes: Option<Vec<u8>>,
    accepts_early_close: bool,
) -> std::io::Result<()> {
    if let Some(mut stdin) = stdin.take() {
        if let Some(bytes) = bytes
            && let Err(error) = stdin.write_all(&bytes).await
        {
            if accepts_early_close && error.kind() == std::io::ErrorKind::BrokenPipe {
                return Ok(());
            }
            return Err(error);
        }
        if let Err(error) = stdin.shutdown().await {
            if accepts_early_close && error.kind() == std::io::ErrorKind::BrokenPipe {
                return Ok(());
            }
            return Err(error);
        }
    }
    Ok(())
}

fn joined_stdin(result: Result<std::io::Result<()>, tokio::task::JoinError>) -> BridgeResult<()> {
    result
        .map_err(|error| BridgeError::new(ErrorCode::Io, error.to_string(), false))?
        .map_err(BridgeError::io)
}

async fn finish_stdin_bounded(mut task: JoinHandle<std::io::Result<()>>) -> BridgeResult<()> {
    match timeout(DRAIN_GRACE, &mut task).await {
        Ok(result) => joined_stdin(result),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(BridgeError::new(
                ErrorCode::Io,
                "SSH stdin writer did not stop after termination",
                false,
            ))
        }
    }
}

fn joined_capture(
    result: Result<BridgeResult<ChildCaptured>, tokio::task::JoinError>,
) -> BridgeResult<ChildCaptured> {
    result.map_err(|error| BridgeError::new(ErrorCode::Io, error.to_string(), false))?
}

fn joined_wait(
    result: Result<std::io::Result<ExitStatus>, tokio::task::JoinError>,
) -> BridgeResult<ExitStatus> {
    result
        .map_err(|error| BridgeError::new(ErrorCode::Io, error.to_string(), false))?
        .map_err(BridgeError::io)
}

async fn finish_wait(task: JoinHandle<std::io::Result<ExitStatus>>) -> BridgeResult<ExitStatus> {
    joined_wait(task.await)
}

async fn finish_capture_bounded(
    mut task: JoinHandle<BridgeResult<ChildCaptured>>,
) -> BridgeResult<ChildCaptured> {
    match timeout(DRAIN_GRACE, &mut task).await {
        Ok(result) => {
            result.map_err(|error| BridgeError::new(ErrorCode::Io, error.to_string(), false))?
        }
        Err(_) => {
            task.abort();
            Err(BridgeError::new(
                ErrorCode::Io,
                "SSH output drain did not stop after termination",
                false,
            ))
        }
    }
}

async fn terminate_process_group(process_group: i32) {
    signal_process_group(process_group, libc::SIGTERM);
    tokio::time::sleep(TERM_GRACE).await;
    signal_process_group(process_group, libc::SIGKILL);
}

fn signal_process_group(process_group: i32, signal: i32) {
    // SAFETY: kill accepts any integer process-group id. The negative id
    // targets only the child-created process group and retains no pointer.
    let result = unsafe { libc::kill(-process_group, signal) };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            // Termination remains best effort; the child is reaped afterward.
        }
    }
}

fn classify_ssh_255(signals: StderrSignals) -> ErrorCode {
    if signals.host_key {
        ErrorCode::HostKeyUnknown
    } else if signals.authentication {
        ErrorCode::AuthRequired
    } else if signals.connect_timeout {
        ErrorCode::ConnectTimeout
    } else {
        ErrorCode::RemoteExit
    }
}

fn cancelled_error(remote_started: bool, bytes_seen: u64) -> BridgeError {
    let mut error = BridgeError::new(ErrorCode::Cancelled, "SSH operation was cancelled", false);
    error.details.remote_process_may_continue = Some(remote_started);
    error.details.bytes_seen = Some(bytes_seen);
    error
}

fn joined_preview(preview: &crate::output::OutputPreview) -> Vec<u8> {
    let mut bytes = preview.head.clone();
    bytes.extend_from_slice(&preview.tail);
    bytes
}

fn hex_digest(digest: &[u8]) -> String {
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn elapsed_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{
        ChildSpec, FixedOperationKind, Phase, SshRunner, capability_probe_command,
        mutation_unknown, render_fixed_command, render_fixed_command_text,
    };
    use crate::capability::parse_probe_output;
    use crate::capability::{ShellKind, ShellSelection};
    use crate::config::{Config, HostProfile};
    use crate::error::{BridgeError, ErrorCode};
    use crate::output::{CaptureLimits, InternalSpoolOwner, OutputStore};
    use crate::path::RemotePath;
    use crate::ssh::{HostSession, RuntimePaths, SessionAction, SessionOutput, SessionRequest};
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::duplex;
    use tokio::time::{Instant, sleep, timeout};
    use tokio_util::sync::CancellationToken;

    #[test]
    fn capability_probe_command_binds_hostile_root_as_positional_one() {
        let filesystem = tempfile::TempDir::new().unwrap();
        for component in ["quote'root", "line\nroot", "-leading-root"] {
            let root = filesystem.path().join(component);
            std::fs::create_dir(&root).unwrap();
            let root = root.to_str().unwrap();
            let command = capability_probe_command(root).unwrap();
            let scratch = tempfile::TempDir::new().unwrap();
            let output = std::process::Command::new("/bin/sh")
                .args(["-c", &command])
                .env("TMPDIR", scratch.path())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "root={root:?}\ncommand={command:?}\nstderr={}",
                String::from_utf8_lossy(&output.stderr)
            );
            let expected = RemotePath::resolve(root, ".").unwrap();
            let capability = parse_probe_output(&output.stdout, &expected).unwrap();
            assert_eq!(capability.physical_root, root);
        }
    }

    #[test]
    fn task78_quote_admission_release_rss() {
        run_quote_admission_release_rss();
    }

    fn run_quote_admission_release_rss() {
        const CHILD_ENV: &str = "CODEX_SSH_BRIDGE_QUOTE_RSS_CHILD";
        const TEST_NAME: &str = "ssh::process::tests::task78_quote_admission_release_rss";
        if cfg!(debug_assertions) {
            eprintln!("quote admission RSS assertion is release-only");
            return;
        }
        if std::env::var_os(CHILD_ENV).is_some() {
            quote_admission_rss_child();
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(CHILD_ENV, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprint!("{stdout}");
        eprint!("{stderr}");
        assert!(output.status.success(), "fresh quote RSS child failed");
        assert!(
            stdout.contains("quote admission release RSS:")
                || stderr.contains("quote admission release RSS:"),
            "fresh quote RSS child did not run the requested test"
        );
    }

    fn quote_admission_rss_child() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Barrier};

        const WORKERS: usize = 5;
        const ROUNDS: usize = 16;
        const RSS_DELTA_CEILING_KIB: u64 = 16 * 1024;

        let commands: Vec<_> = (0..WORKERS)
            .map(|_| Arc::new("'".repeat(crate::MAX_FRAME_BYTES)))
            .collect();
        assert!(
            commands
                .iter()
                .all(|command| command.len() == crate::MAX_FRAME_BYTES)
        );
        let warmed = commands
            .iter()
            .flat_map(|command| command.as_bytes().iter().step_by(4096))
            .fold(0u8, |sum, byte| sum.wrapping_add(*byte));
        std::hint::black_box(warmed);

        let start = Arc::new(Barrier::new(WORKERS + 1));
        let finish = Arc::new(Barrier::new(WORKERS + 1));
        let completed = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::with_capacity(WORKERS);
        for command in commands {
            let start = Arc::clone(&start);
            let finish = Arc::clone(&finish);
            let completed = Arc::clone(&completed);
            workers.push(std::thread::spawn(move || {
                start.wait();
                let mut last_error = None;
                for _ in 0..ROUNDS {
                    let error = render_fixed_command_text(
                        "printf %s \"$1\"",
                        &[command.as_ref().clone()],
                        crate::MAX_FRAME_BYTES,
                    )
                    .unwrap_err();
                    assert_eq!(error.code, ErrorCode::RequestTooLarge);
                    assert_eq!(
                        error.message,
                        "rendered command exceeds the configured frame limit"
                    );
                    last_error = Some(error);
                }
                completed.fetch_add(1, Ordering::Release);
                finish.wait();
                last_error.unwrap().code
            }));
        }

        let baseline = resident_kib_for_rss_test();
        let mut peak = baseline;
        start.wait();
        while completed.load(Ordering::Acquire) != WORKERS {
            peak = peak.max(resident_kib_for_rss_test());
            std::thread::sleep(Duration::from_micros(250));
        }
        for _ in 0..20 {
            peak = peak.max(resident_kib_for_rss_test());
            std::thread::sleep(Duration::from_millis(1));
        }
        finish.wait();
        for worker in workers {
            assert_eq!(worker.join().unwrap(), ErrorCode::RequestTooLarge);
        }
        let delta = peak.saturating_sub(baseline);
        eprintln!(
            "quote admission release RSS: baseline={baseline} KiB peak={peak} KiB delta={delta} KiB ceiling={RSS_DELTA_CEILING_KIB} KiB"
        );
        assert!(
            delta < RSS_DELTA_CEILING_KIB,
            "quote admission RSS baseline={baseline} peak={peak} delta={delta}"
        );
    }

    fn resident_kib_for_rss_test() -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|line| {
                line.strip_prefix("VmRSS:")
                    .and_then(|value| value.split_whitespace().next())
                    .and_then(|value| value.parse().ok())
            })
            .unwrap()
    }

    #[test]
    fn fixed_runner_render_uses_static_script_and_positional_values() {
        let rendered = render_fixed_command(
            "printf '%s\\0' \"$@\"",
            &[
                "quote'".to_owned(),
                "line\n$()`".to_owned(),
                "-x".to_owned(),
            ],
        )
        .unwrap();
        assert!(rendered.starts_with("exec sh -c "));
        assert!(rendered.contains(" codex-ssh-bridge-op "));
        let output = std::process::Command::new("/bin/sh")
            .args(["-c", &rendered])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"quote'\0line\n$()`\0-x\0");
    }

    #[test]
    fn fixed_rendering_has_no_physical_root_protocol() {
        let fixed = render_fixed_command("printf ok", &[]).unwrap();
        assert!(!fixed.contains("CODEX_SSH_ROOT_OBSERVE"));
        assert!(!fixed.contains("237"));
    }

    #[test]
    fn task5_mutation_unknown_is_closed_non_retryable_and_preserves_safe_context() {
        let mut source = BridgeError::new(ErrorCode::RemoteExit, "untrusted detail", true);
        source.details.host = Some("dev".to_owned());
        source.details.elapsed_ms = Some(17);
        source.details.exit_status = Some(255);
        source.details.bytes_seen = Some(23);
        source.details.remote_process_may_continue = Some(true);

        let error = mutation_unknown(source);
        assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
        assert_eq!(
            error.message,
            "remote mutation outcome could not be confirmed"
        );
        assert!(!error.retryable);
        assert_eq!(error.details.host.as_deref(), Some("dev"));
        assert_eq!(error.details.elapsed_ms, Some(17));
        assert_eq!(error.details.exit_status, Some(255));
        assert_eq!(error.details.bytes_seen, Some(23));
        assert_eq!(error.details.remote_process_may_continue, Some(true));
        assert_eq!(error.details.mutation_may_have_applied, Some(true));
    }

    fn task5_test_runner(executable: &str) -> (tempfile::TempDir, SshRunner) {
        let base = tempfile::TempDir::new().unwrap();
        let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
        let output = Arc::new(OutputStore::new(&runtime).unwrap());
        let runner = SshRunner::with_executable(
            Arc::new(Config::default()),
            runtime,
            output,
            PathBuf::from(executable),
            BTreeMap::<OsString, OsString>::new(),
        )
        .unwrap();
        (base, runner)
    }

    #[tokio::test]
    async fn session_failure_cancels_output_capture_before_waiting_for_eof() {
        let (_base, runner) = task5_test_runner("/bin/false");
        let session = Arc::new(HostSession::wedged_for_test(
            "dev",
            crate::MAX_FRAME_BYTES,
            crate::MAX_OUTPUT_BYTES,
        ));
        let (stdout_writer, stdout_reader) = duplex(64 * 1024);
        let (stderr_writer, stderr_reader) = duplex(64 * 1024);
        let capture_cancel = CancellationToken::new();
        let capture = runner.output_store.capture(
            stdout_reader,
            stderr_reader,
            CaptureLimits {
                preview_bytes: 1024,
                max_output_bytes: 1024 * 1024,
            },
            capture_cancel.clone(),
        );
        let request = SessionRequest {
            action: SessionAction::Command {
                command: "true".to_owned(),
                cwd: "/".to_owned(),
                shell: ShellSelection {
                    shell: ShellKind::PosixSh,
                    fallback: false,
                },
                login_shell: None,
                stdin: None,
            },
            env: BTreeMap::new(),
            timeout: Duration::from_secs(5),
            admission_deadline: Instant::now() + Duration::from_millis(25),
            response_timeout: Duration::from_secs(5),
            stdout_limit: 1024 * 1024,
            stderr_limit: 1024 * 1024,
            output: Some(SessionOutput {
                stdout: stdout_writer,
                stderr: stderr_writer,
            }),
        };

        let error = timeout(
            Duration::from_millis(500),
            runner.execute_with_capture(
                &session,
                request,
                capture,
                CancellationToken::new(),
                capture_cancel,
            ),
        )
        .await
        .expect("session failure waited indefinitely for output EOF")
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::CommandTimeout);
        assert_eq!(error.details.remote_process_may_continue, Some(true));
    }

    struct Task5FixedFixture {
        _base: tempfile::TempDir,
        runtime: RuntimePaths,
        runner: Arc<SshRunner>,
    }

    fn task5_fixed_fixture(environment: &[(&str, String)]) -> Task5FixedFixture {
        task5_fixed_fixture_with_limits(environment, crate::config::Limits::default())
    }

    fn task5_fixed_fixture_with_limits(
        environment: &[(&str, String)],
        limits: crate::config::Limits,
    ) -> Task5FixedFixture {
        let base = tempfile::TempDir::new().unwrap();
        let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
        let output = Arc::new(OutputStore::new(&runtime).unwrap());
        let mut config = Config {
            limits,
            ..Config::default()
        };
        config.hosts.insert(
            "dev".to_owned(),
            HostProfile {
                root: "/srv/project".to_owned(),
                description: None,
                read_only: false,
                limits: Default::default(),
            },
        );
        let environment = environment
            .iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value)))
            .chain([(OsString::from("FAKE_SSH_ROOT"), OsString::from("/"))])
            .collect();
        let executable =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-ssh.sh");
        let runner = Arc::new(
            SshRunner::with_executable(
                Arc::new(config),
                runtime.clone(),
                output,
                executable,
                environment,
            )
            .unwrap(),
        );
        Task5FixedFixture {
            _base: base,
            runtime,
            runner,
        }
    }

    fn task5_fixed_request(
        kind: FixedOperationKind,
        timeout: Duration,
        cleanup: crate::output::InternalSpoolRegistration,
        stdout_limit: u64,
        stderr_limit: u64,
    ) -> super::FixedRunRequest {
        super::FixedRunRequest {
            kind,
            host: "dev".to_owned(),
            script: "exit 0",
            args: Vec::new(),
            stdin: None,
            rooted_paths: super::RootedPathInputs::default(),
            required_capabilities: &["safe_write"],
            stdout_limit,
            stderr_limit,
            timeout,
            cleanup,
        }
    }

    fn task5_call_count(log: &std::path::Path, marker: &str) -> usize {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .filter(|line| *line == marker)
            .count()
    }

    async fn task5_wait_for_call(log: &std::path::Path, marker: &str) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while task5_call_count(log, marker) == 0 {
            assert!(Instant::now() < deadline, "missing {marker} call");
            sleep(Duration::from_millis(5)).await;
        }
    }

    fn task5_internal_spool_file_count(runtime: &RuntimePaths) -> usize {
        std::fs::read_dir(runtime.directory())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
            .flat_map(|entry| {
                std::fs::read_dir(entry.path())
                    .into_iter()
                    .flatten()
                    .filter_map(Result::ok)
            })
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
            .count()
    }

    fn task5_child(script: &str, kind: FixedOperationKind, deadline: Duration) -> ChildSpec {
        ChildSpec {
            argv: vec![OsString::from("-c"), OsString::from(script)],
            stdin: None,
            capture_limits: CaptureLimits {
                preview_bytes: 1,
                max_output_bytes: 1024,
            },
            deadline,
            phase: Phase::Fixed { kind },
            internal_registration: None,
        }
    }

    #[tokio::test]
    async fn task5_mutation_phase_marks_only_post_spawn_ambiguity() {
        let (_base, runner) = task5_test_runner("/bin/sh");

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let error = runner
            .run_child(
                task5_child(
                    "exit 0",
                    FixedOperationKind::Mutation,
                    Duration::from_secs(1),
                ),
                &cancelled,
                "dev",
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::Cancelled);
        assert_eq!(error.details.mutation_may_have_applied, None);

        let error = runner
            .run_child(
                task5_child(
                    "exit 7",
                    FixedOperationKind::Mutation,
                    Duration::from_secs(1),
                ),
                &CancellationToken::new(),
                "dev",
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
        assert_eq!(error.details.exit_status, Some(7));
        assert_eq!(error.details.mutation_may_have_applied, Some(true));

        let error = runner
            .run_child(
                task5_child(
                    "sleep 1",
                    FixedOperationKind::Mutation,
                    Duration::from_millis(10),
                ),
                &CancellationToken::new(),
                "dev",
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
        assert_eq!(error.details.mutation_may_have_applied, Some(true));

        let error = runner
            .run_child(
                task5_child(
                    "exit 7",
                    FixedOperationKind::ReadOnly,
                    Duration::from_secs(1),
                ),
                &CancellationToken::new(),
                "dev",
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::RemoteExit);
        assert_eq!(error.details.mutation_may_have_applied, None);

        let mut readonly = task5_child(
            "exit 0",
            FixedOperationKind::ReadOnly,
            Duration::from_secs(1),
        );
        readonly.stdin = Some(vec![b'x'; 4 * 1024 * 1024]);
        let error = runner
            .run_child(readonly, &CancellationToken::new(), "dev")
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::Io);
        assert_eq!(error.details.mutation_may_have_applied, None);

        let (_missing_base, missing_runner) = task5_test_runner("/no/such/task5-ssh");
        let error = missing_runner
            .run_child(
                task5_child(
                    "exit 0",
                    FixedOperationKind::Mutation,
                    Duration::from_secs(1),
                ),
                &CancellationToken::new(),
                "dev",
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::Io);
        assert_eq!(error.details.mutation_may_have_applied, None);
    }

    #[tokio::test]
    async fn task5_execute_fixed_once_maps_only_spawned_mutations_and_never_retries() {
        let logs = tempfile::TempDir::new().unwrap();

        let cached_false_log = logs.path().join("cached-false.log");
        let fixture = task5_fixed_fixture(&[
            ("FAKE_SSH_LOG", cached_false_log.display().to_string()),
            ("FAKE_SSH_HAS_SAFE_WRITE", "0".to_owned()),
        ]);
        let owner = InternalSpoolOwner::new();
        let error = fixture
            .runner
            .execute_fixed_once(
                task5_fixed_request(
                    FixedOperationKind::Mutation,
                    Duration::from_secs(1),
                    owner.registration(),
                    16,
                    16,
                ),
                CancellationToken::new(),
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::RemoteCapabilityMissing);
        assert_eq!(error.details.mutation_may_have_applied, None);
        assert_eq!(task5_call_count(&cached_false_log, "C"), 0);
        drop(owner);
        assert_eq!(task5_internal_spool_file_count(&fixture.runtime), 0);

        let pre_cancel_log = logs.path().join("pre-cancel.log");
        let fixture =
            task5_fixed_fixture(&[("FAKE_SSH_LOG", pre_cancel_log.display().to_string())]);
        let owner = InternalSpoolOwner::new();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let error = fixture
            .runner
            .execute_fixed_once(
                task5_fixed_request(
                    FixedOperationKind::Mutation,
                    Duration::from_secs(1),
                    owner.registration(),
                    16,
                    16,
                ),
                cancel,
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::Cancelled);
        assert_eq!(error.details.mutation_may_have_applied, None);
        assert_eq!(task5_call_count(&pre_cancel_log, "C"), 0);
        drop(owner);
        assert_eq!(task5_internal_spool_file_count(&fixture.runtime), 0);

        let probe_cancel_log = logs.path().join("probe-cancel.log");
        let fixture = task5_fixed_fixture(&[
            ("FAKE_SSH_LOG", probe_cancel_log.display().to_string()),
            ("FAKE_SSH_PROBE_SLEEP_SECONDS", "5".to_owned()),
        ]);
        let owner = InternalSpoolOwner::new();
        let cancel = CancellationToken::new();
        let task = tokio::spawn({
            let runner = Arc::clone(&fixture.runner);
            let cancel = cancel.clone();
            let request = task5_fixed_request(
                FixedOperationKind::Mutation,
                Duration::from_secs(1),
                owner.registration(),
                16,
                16,
            );
            async move { runner.execute_fixed_once(request, cancel).await }
        });
        task5_wait_for_call(&probe_cancel_log, "P").await;
        cancel.cancel();
        let error = task.await.unwrap().err().unwrap();
        assert_eq!(error.code, ErrorCode::Cancelled);
        assert_eq!(error.details.mutation_may_have_applied, None);
        assert_eq!(task5_call_count(&probe_cancel_log, "C"), 0);
        drop(owner);
        assert_eq!(task5_internal_spool_file_count(&fixture.runtime), 0);

        for (name, exit_status) in [("exit7", 7), ("status255", 255)] {
            let log = logs.path().join(format!("{name}.log"));
            let fixture = task5_fixed_fixture(&[
                ("FAKE_SSH_LOG", log.display().to_string()),
                ("FAKE_SSH_MODE", "error".to_owned()),
                ("FAKE_SSH_ERROR", "remote".to_owned()),
                ("FAKE_SSH_EXIT_STATUS", exit_status.to_string()),
            ]);
            let owner = InternalSpoolOwner::new();
            let error = fixture
                .runner
                .execute_fixed_once(
                    task5_fixed_request(
                        FixedOperationKind::Mutation,
                        Duration::from_secs(1),
                        owner.registration(),
                        16,
                        64,
                    ),
                    CancellationToken::new(),
                )
                .await
                .err()
                .unwrap();
            assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown, "{name}");
            assert_eq!(error.details.exit_status, Some(exit_status), "{name}");
            assert_eq!(error.details.mutation_may_have_applied, Some(true));
            assert_eq!(task5_call_count(&log, "C"), 1, "{name}");
            drop(owner);
            assert_eq!(task5_internal_spool_file_count(&fixture.runtime), 0);
        }

        let timeout_log = logs.path().join("timeout.log");
        let fixture = task5_fixed_fixture(&[
            ("FAKE_SSH_LOG", timeout_log.display().to_string()),
            ("FAKE_SSH_MODE", "sleep".to_owned()),
            ("FAKE_SSH_SLEEP_SECONDS", "5".to_owned()),
        ]);
        let owner = InternalSpoolOwner::new();
        let error = fixture
            .runner
            .execute_fixed_once(
                task5_fixed_request(
                    FixedOperationKind::Mutation,
                    Duration::from_millis(200),
                    owner.registration(),
                    16,
                    16,
                ),
                CancellationToken::new(),
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
        assert_eq!(error.details.mutation_may_have_applied, Some(true));
        assert_eq!(task5_call_count(&timeout_log, "C"), 1);
        drop(owner);
        assert_eq!(task5_internal_spool_file_count(&fixture.runtime), 0);

        let cancel_log = logs.path().join("spawn-cancel.log");
        let fixture = task5_fixed_fixture(&[
            ("FAKE_SSH_LOG", cancel_log.display().to_string()),
            ("FAKE_SSH_MODE", "sleep".to_owned()),
            ("FAKE_SSH_SLEEP_SECONDS", "5".to_owned()),
        ]);
        let owner = InternalSpoolOwner::new();
        let cancel = CancellationToken::new();
        let task = tokio::spawn({
            let runner = Arc::clone(&fixture.runner);
            let cancel = cancel.clone();
            let request = task5_fixed_request(
                FixedOperationKind::Mutation,
                Duration::from_secs(5),
                owner.registration(),
                16,
                16,
            );
            async move { runner.execute_fixed_once(request, cancel).await }
        });
        task5_wait_for_call(&cancel_log, "C").await;
        cancel.cancel();
        let error = task.await.unwrap().err().unwrap();
        assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
        assert_eq!(error.details.mutation_may_have_applied, Some(true));
        assert_eq!(task5_call_count(&cancel_log, "C"), 1);
        drop(owner);
        assert_eq!(task5_internal_spool_file_count(&fixture.runtime), 0);

        let overflow_log = logs.path().join("overflow.log");
        let fixture = task5_fixed_fixture(&[
            ("FAKE_SSH_LOG", overflow_log.display().to_string()),
            ("FAKE_SSH_MODE", "bytes".to_owned()),
            ("FAKE_SSH_FIXED_STDOUT_BYTES", "64".to_owned()),
        ]);
        let owner = InternalSpoolOwner::new();
        let error = fixture
            .runner
            .execute_fixed_once(
                task5_fixed_request(
                    FixedOperationKind::Mutation,
                    Duration::from_secs(1),
                    owner.registration(),
                    16,
                    16,
                ),
                CancellationToken::new(),
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
        assert_eq!(error.details.mutation_may_have_applied, Some(true));
        assert_eq!(task5_call_count(&overflow_log, "C"), 1);
        drop(owner);
        assert_eq!(task5_internal_spool_file_count(&fixture.runtime), 0);

        // A closed registration forces internal capture setup to fail after
        // local spawn. The child races that asynchronous setup and may reach
        // the fixture log first, which is precisely why the mutation outcome
        // is unknown. The pending spool is armed and unlinked on drop, and the
        // child remains kill-on-drop if any post-spawn pid/pipe invariant ever
        // fails before the wait task takes ownership.
        let setup_log = logs.path().join("capture-setup.log");
        let fixture = task5_fixed_fixture(&[
            ("FAKE_SSH_LOG", setup_log.display().to_string()),
            ("FAKE_SSH_MODE", "streams".to_owned()),
        ]);
        let owner = InternalSpoolOwner::new();
        let registration = owner.registration();
        drop(owner);
        let error = fixture
            .runner
            .execute_fixed_once(
                task5_fixed_request(
                    FixedOperationKind::Mutation,
                    Duration::from_secs(1),
                    registration,
                    16,
                    16,
                ),
                CancellationToken::new(),
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
        assert_eq!(error.details.mutation_may_have_applied, Some(true));
        assert!(task5_call_count(&setup_log, "C") <= 1);
        assert_eq!(task5_internal_spool_file_count(&fixture.runtime), 0);
    }

    #[tokio::test]
    async fn fixed_setup_consumes_one_connect_budget_across_probe_and_session_start() {
        let logs = tempfile::TempDir::new().unwrap();
        let log = logs.path().join("fixed-connect-budget.log");
        let limits = crate::config::Limits {
            connect_timeout_ms: 300,
            ..crate::config::Limits::default()
        };
        let fixture = task5_fixed_fixture_with_limits(
            &[
                ("FAKE_SSH_LOG", log.display().to_string()),
                ("FAKE_SSH_PROBE_SLEEP_SECONDS", "0.2".to_owned()),
                ("FAKE_SSH_SESSION_START_SLEEP_SECONDS", "0.2".to_owned()),
            ],
            limits,
        );
        let owner = InternalSpoolOwner::new();

        let started = Instant::now();
        let result = fixture
            .runner
            .execute_fixed_once(
                task5_fixed_request(
                    FixedOperationKind::ReadOnly,
                    Duration::from_secs(2),
                    owner.registration(),
                    16,
                    16,
                ),
                CancellationToken::new(),
            )
            .await;
        let error = match result {
            Ok(_) => panic!("fixed setup unexpectedly received a fresh connect budget"),
            Err(error) => error,
        };

        assert_eq!(error.code, ErrorCode::ConnectTimeout);
        assert!(
            started.elapsed() < Duration::from_millis(600),
            "fixed setup exceeded one connect budget plus bounded cleanup: {:?}",
            started.elapsed()
        );
        assert_eq!(task5_call_count(&log, "P"), 1);
        assert_eq!(task5_call_count(&log, "S"), 1);
        assert_eq!(task5_call_count(&log, "C"), 0);
    }
}
