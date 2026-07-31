#![allow(
    clippy::result_large_err,
    reason = "the crate's public BridgeResult intentionally stores BridgeError inline"
)]

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::capability::{MAX_SHELL_VERSION_BYTES, ShellKind, ShellSelection};
use crate::config::{Config, EffectiveLimits};
use crate::error::{
    BridgeError, BridgeResult, ErrorCode, ErrorShellMetadata, attach_available_remote_context,
};
use crate::output::{
    OutputProvenance, OutputReference, StoredAggregateKind, StoredProvenance, StreamKind,
};
use crate::path::RemotePath;
use crate::ssh::{FixedRunRequest, FixedRunResult, HelperMode, SshRunner};

mod edit_cache;
mod edit_sync;
mod job;
mod metadata;
mod patch;
mod protocol;
mod read;
mod run;
mod search;
mod write;

pub use job::{
    RemoteJobDeleteResult, RemoteJobIdRequest, RemoteJobListRequest, RemoteJobListResult,
    RemoteJobLogsRequest, RemoteJobLogsResult, RemoteJobStartRequest, RemoteJobStartResult,
    RemoteJobStatusResult,
};

const MAX_INPUT_PATH_BYTES: usize = 64 * 1024;
const MAX_STAT_PATHS: usize = 256;
const MAX_READ_PATHS: usize = 32;
const DEFAULT_LIST_DEPTH: u32 = 1;
const MAX_LIST_DEPTH: u32 = 32;
const DEFAULT_LIST_ENTRIES: usize = 1_000;
const MAX_LIST_ENTRIES: usize = 10_000;
const DEFAULT_SEARCH_RESULTS: usize = 100;
const MAX_SEARCH_RESULTS: usize = 10_000;
const MAX_QUERY_BYTES: usize = 64 * 1024;
const MAX_GLOBS: usize = 128;
const MAX_GLOB_BYTES: usize = 4 * 1024;
const DEFAULT_START_LINE: u64 = 1;
const DEFAULT_MAX_LINES: u64 = 2_000;
const MAX_LINES: u64 = 100_000;
const MAX_EDIT_BARRIER_WAIT: Duration = Duration::from_secs(30);

pub(crate) const POSIX_SH_WARNING: &str = "selected POSIX sh does not support Bash arrays, [[ ]], source, pipefail, or Bash substitutions; use POSIX syntax, or request Bash and ensure it is installed";

pub struct RemoteBridge {
    runner: Arc<SshRunner>,
    edit_backend: Arc<edit_sync::SshEditBackend>,
    edit_cache: Arc<edit_cache::EditCache>,
    edit_buffering_enabled: bool,
}

fn attach_fixed_result_context(
    mut error: BridgeError,
    host: &str,
    result: &FixedRunResult,
) -> BridgeError {
    error = attach_shell_selection_context(
        error,
        host,
        &result.capability.physical_root,
        &result.shell,
    );
    if error.details.elapsed_ms.is_none() {
        error.details.elapsed_ms = Some(result.elapsed_ms);
    }
    if error.details.bytes_seen.is_none() {
        error.details.bytes_seen = Some(result.output.aggregate_bytes);
    }
    if error.details.remote_process_may_continue.is_none() {
        error.details.remote_process_may_continue = Some(result.remote_process_may_continue);
    }
    error
}

fn attach_shell_selection_context(
    mut error: BridgeError,
    host: &str,
    physical_root: &str,
    shell: &crate::capability::ShellSelection,
) -> BridgeError {
    let metadata = protocol::shell_selection_metadata(shell);
    let shell = ErrorShellMetadata {
        kind: match metadata.kind {
            ShellName::Bash => "bash",
            ShellName::Sh => "sh",
            ShellName::Login => "login",
        }
        .to_owned(),
        version: metadata.version,
        fallback: metadata.fallback,
    };
    attach_available_remote_context(&mut error, Some(host), Some(physical_root), Some(&shell));
    error
}

fn attach_remote_context(mut error: BridgeError, context: &RemoteContext) -> BridgeError {
    let shell = ErrorShellMetadata {
        kind: match context.shell.kind {
            ShellName::Bash => "bash",
            ShellName::Sh => "sh",
            ShellName::Login => "login",
        }
        .to_owned(),
        version: context.shell.version.clone(),
        fallback: context.shell.fallback,
    };
    attach_available_remote_context(
        &mut error,
        Some(&context.host),
        Some(&context.physical_root),
        Some(&shell),
    );
    error
}

fn attach_retention_context(error: BridgeError, provenance: &RetentionProvenance) -> BridgeError {
    match provenance {
        RetentionProvenance::Remote(context) => attach_remote_context(error, context),
        RetentionProvenance::Aggregate { .. } => error,
    }
}

fn invalid_retention_provenance() -> BridgeError {
    BridgeError::invalid_argument("retention provenance does not match a cached remote capability")
}

fn attach_optional_remote_context(
    error: BridgeError,
    context: Option<&RemoteContext>,
) -> BridgeError {
    match context {
        Some(context) => attach_remote_context(error, context),
        None => error,
    }
}

fn edit_bridge_error(error: edit_cache::EditError) -> BridgeError {
    if let Some(code) = error.code
        && error.kind != edit_cache::EditErrorKind::OutcomeUnknown
    {
        return BridgeError::new(
            edit_error_code(code),
            error.message,
            error.kind == edit_cache::EditErrorKind::Transient,
        );
    }
    match error.kind {
        edit_cache::EditErrorKind::Conflict => {
            BridgeError::new(ErrorCode::WriteConflict, error.message, false)
        }
        edit_cache::EditErrorKind::OutcomeUnknown => {
            let mut bridge_error = BridgeError::mutation_outcome_unknown();
            bridge_error.message = error.message;
            bridge_error
        }
        edit_cache::EditErrorKind::Permanent => {
            BridgeError::new(ErrorCode::InvalidArgument, error.message, false)
        }
        edit_cache::EditErrorKind::Transient => {
            BridgeError::new(ErrorCode::Io, error.message, true)
        }
    }
}

fn edit_error_code(code: edit_cache::EditErrorCode) -> ErrorCode {
    match code {
        edit_cache::EditErrorCode::HostKeyUnknown => ErrorCode::HostKeyUnknown,
        edit_cache::EditErrorCode::AuthRequired => ErrorCode::AuthRequired,
        edit_cache::EditErrorCode::ConnectTimeout => ErrorCode::ConnectTimeout,
        edit_cache::EditErrorCode::RemoteCapabilityMissing => ErrorCode::RemoteCapabilityMissing,
        edit_cache::EditErrorCode::RemoteAbsolutePathRequired => {
            ErrorCode::RemoteAbsolutePathRequired
        }
        edit_cache::EditErrorCode::PathOutsideRoot => ErrorCode::PathOutsideRoot,
        edit_cache::EditErrorCode::ReadOnlyHost => ErrorCode::ReadOnlyHost,
        edit_cache::EditErrorCode::WriteConflict => ErrorCode::WriteConflict,
        edit_cache::EditErrorCode::ReadConflict => ErrorCode::ReadConflict,
        edit_cache::EditErrorCode::NotFound => ErrorCode::NotFound,
        edit_cache::EditErrorCode::PermissionDenied => ErrorCode::PermissionDenied,
        edit_cache::EditErrorCode::NotDirectory => ErrorCode::NotDirectory,
        edit_cache::EditErrorCode::MutationOutcomeUnknown => ErrorCode::MutationOutcomeUnknown,
        edit_cache::EditErrorCode::OutputLimit => ErrorCode::OutputLimit,
        edit_cache::EditErrorCode::RequestTooLarge => ErrorCode::RequestTooLarge,
        edit_cache::EditErrorCode::ProtocolError => ErrorCode::ProtocolError,
        edit_cache::EditErrorCode::Cancelled => ErrorCode::Cancelled,
        edit_cache::EditErrorCode::CommandTimeout => ErrorCode::CommandTimeout,
        edit_cache::EditErrorCode::RemoteExit => ErrorCode::RemoteExit,
        edit_cache::EditErrorCode::InvalidConfig => ErrorCode::InvalidConfig,
        edit_cache::EditErrorCode::InvalidArgument => ErrorCode::InvalidArgument,
        edit_cache::EditErrorCode::Io => ErrorCode::Io,
    }
}

impl RemoteBridge {
    pub fn new(runner: Arc<SshRunner>) -> Self {
        Self::new_with_edit_buffering(runner, true)
    }

    #[doc(hidden)]
    pub fn new_immediate_for_transport_tests(runner: Arc<SshRunner>) -> Self {
        Self::new_with_edit_buffering(runner, false)
    }

    fn new_with_edit_buffering(runner: Arc<SshRunner>, edit_buffering_enabled: bool) -> Self {
        let edit_limits = &runner.config().limits;
        let edit_backend =
            edit_sync::SshEditBackend::new(Arc::clone(&runner), edit_limits.edit_cache_max_bytes);
        let edit_cache = edit_cache::EditCache::new(
            edit_cache::EditCacheConfig {
                flush_delay: std::time::Duration::from_millis(edit_limits.edit_flush_delay_ms),
                flush_threshold_bytes: edit_limits.edit_flush_threshold_bytes,
                max_bytes: edit_limits.edit_cache_max_bytes,
            },
            edit_backend.clone(),
        );
        Self {
            runner,
            edit_backend,
            edit_cache,
            edit_buffering_enabled,
        }
    }

    pub async fn hosts(&self) -> BridgeResult<HostsResult> {
        let hosts = self
            .runner
            .config()
            .discover_hosts()
            .into_iter()
            .map(|host| HostInfo { host: host.alias })
            .collect();
        Ok(HostsResult { hosts })
    }

    pub async fn shutdown(&self) -> BridgeResult<()> {
        self.edit_cache.shutdown().await.map_err(edit_bridge_error)
    }

    pub async fn edit_status(&self, request: EditStatusRequest) -> BridgeResult<EditStatusResult> {
        self.runner
            .config()
            .require_discovered_alias(&request.host)?;
        let status = self.edit_cache.host_status(&request.host).await;
        Ok(EditStatusResult {
            remote: true,
            host: request.host,
            pending_paths: status.pending_paths,
            outcome_unknown_paths: status.outcome_unknown_paths,
            pending_payload_bytes: status.pending_payload_bytes,
            cached_bytes: status.cached_bytes,
        })
    }

    pub async fn sync_edits(&self, request: SyncEditsRequest) -> BridgeResult<SyncEditsResult> {
        self.runner
            .config()
            .require_discovered_alias(&request.host)?;
        let _guard = self.edit_cache.begin_barrier(&request.host).await;
        if let Err(error) = self
            .edit_cache
            .retry_outcome_unknown_host(&request.host)
            .await
        {
            let error = edit_bridge_error(error);
            return Err(match self.edit_backend.context_for(&request.host).await {
                Some(context) => attach_remote_context(error, &context),
                None => error,
            });
        }
        let status = self.edit_cache.host_status(&request.host).await;
        Ok(SyncEditsResult {
            remote: true,
            host: request.host,
            pending_paths: status.pending_paths,
            outcome_unknown_paths: status.outcome_unknown_paths,
            pending_payload_bytes: status.pending_payload_bytes,
        })
    }

    pub async fn discard_edits(
        &self,
        request: DiscardEditsRequest,
    ) -> BridgeResult<DiscardEditsResult> {
        self.runner
            .config()
            .require_discovered_alias(&request.host)?;
        let _guard = self.edit_cache.begin_barrier(&request.host).await;
        let discarded = self.edit_cache.discard_host_edits(&request.host).await;
        let status = self.edit_cache.host_status(&request.host).await;
        Ok(DiscardEditsResult {
            remote: true,
            host: request.host,
            discarded_paths: discarded.discarded_paths,
            discarded_payload_bytes: discarded.discarded_payload_bytes,
            had_outcome_unknown: discarded.had_outcome_unknown,
            pending_paths: status.pending_paths,
            outcome_unknown_paths: status.outcome_unknown_paths,
        })
    }

    pub async fn list(
        &self,
        request: ListRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<ListResult> {
        let resolved = resolve_list(self.runner.config(), request)?;
        self.edit_barrier(&resolved.host, cancel.clone()).await?;
        metadata::list(self, resolved, cancel).await
    }

    pub async fn stat(
        &self,
        request: StatRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<StatResult> {
        let resolved = resolve_stat(self.runner.config(), request)?;
        self.edit_barrier(&resolved.host, cancel.clone()).await?;
        metadata::stat(self, resolved, cancel).await
    }

    pub async fn read(
        &self,
        request: ReadRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<ReadResult> {
        let resolved = resolve_read(self.runner.config(), request)?;
        read::read(self, resolved, cancel).await
    }

    pub async fn search(
        &self,
        request: SearchRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<SearchResult> {
        let resolved = resolve_search(self.runner.config(), request)?;
        self.edit_barrier(&resolved.host, cancel.clone()).await?;
        search::search(self, resolved, cancel).await
    }

    pub async fn run(
        &self,
        request: RemoteRunRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<RemoteRunResult> {
        self.runner
            .config()
            .require_discovered_alias(&request.host)?;
        let host = request.host.clone();
        self.edit_barrier(&host, cancel.clone()).await?;
        let result = run::run(self, request, cancel).await?;
        self.edit_cache.invalidate_clean_host(&host).await;
        Ok(result)
    }

    pub async fn job_start(
        &self,
        request: RemoteJobStartRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<RemoteJobStartResult> {
        job::start(self, request, cancel).await
    }

    pub async fn job_status(
        &self,
        request: RemoteJobIdRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<RemoteJobStatusResult> {
        job::status(self, request, cancel).await
    }

    pub async fn job_logs(
        &self,
        request: RemoteJobLogsRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<RemoteJobLogsResult> {
        job::logs(self, request, cancel).await
    }

    pub async fn job_cancel(
        &self,
        request: RemoteJobIdRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<RemoteJobStatusResult> {
        job::cancel(self, request, cancel).await
    }

    pub async fn job_list(
        &self,
        request: RemoteJobListRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<RemoteJobListResult> {
        job::list(self, request, cancel).await
    }

    pub async fn job_delete(
        &self,
        request: RemoteJobIdRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<RemoteJobDeleteResult> {
        job::delete(self, request, cancel).await
    }

    pub async fn write(
        &self,
        request: WriteRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<WriteResult> {
        write::write(self, request, cancel).await
    }

    pub async fn apply_patch(
        &self,
        request: ApplyPatchRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<ApplyPatchResult> {
        patch::apply_patch(self, request, cancel).await
    }

    #[allow(dead_code, reason = "reserved for the internal Task 6 patch workflow")]
    pub(crate) async fn guarded_delete(
        &self,
        request: GuardedDeleteRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<GuardedDeleteResult> {
        write::guarded_delete(self, request, cancel).await
    }

    pub async fn output_read(
        &self,
        request: OutputReadRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<OutputReadResult> {
        let reference = crate::output::OutputReference::parse(&request.output_ref)?;
        let provenance = match self.runner.output_provenance(&reference).await? {
            StoredProvenance::Remote(provenance) => RetentionProvenance::Remote(RemoteContext {
                remote: true,
                host: provenance.host,
                physical_root: provenance.physical_root,
                shell: protocol::shell_selection_metadata(&provenance.shell),
                helper_mode: Some(provenance.helper_mode),
            }),
            StoredProvenance::Aggregate { kind, source_count } => RetentionProvenance::Aggregate {
                kind: match kind {
                    StoredAggregateKind::Hosts => AggregateKind::Hosts,
                },
                source_count,
            },
        };
        let page = tokio::select! { biased;
            () = cancel.cancelled() => return Err(attach_retention_context(BridgeError::new(ErrorCode::Cancelled, "output read was cancelled", false), &provenance)),
            page = self.runner.read_output(&reference, request.stream, request.offset, request.max_bytes) => page.map_err(|error| attach_retention_context(error, &provenance))?,
        };
        Ok(OutputReadResult {
            provenance,
            stream: request.stream,
            offset: page.offset,
            next_offset: page.next_offset,
            eof: page.eof,
            data: protocol::encode_bytes(&page.bytes),
        })
    }

    pub async fn retain_serialized_detail<T: Serialize + Send + 'static>(
        &self,
        provenance: RetentionProvenance,
        owned: T,
        cancel: CancellationToken,
    ) -> BridgeResult<OutputReference> {
        let stored = self.resolve_retention_provenance(provenance).await?;
        self.runner
            .retain_serialized_detail(stored, owned, cancel)
            .await
    }

    pub async fn retain_presentation(
        &self,
        provenance: RetentionProvenance,
        owned: String,
        cancel: CancellationToken,
    ) -> BridgeResult<OutputReference> {
        let stored = self.resolve_retention_provenance(provenance).await?;
        self.runner
            .retain_bytes(stored, owned.into_bytes(), cancel)
            .await
    }

    async fn resolve_retention_provenance(
        &self,
        provenance: RetentionProvenance,
    ) -> BridgeResult<StoredProvenance> {
        Ok(match provenance {
            RetentionProvenance::Remote(context) => {
                if !context.remote {
                    return Err(invalid_retention_provenance());
                }
                let Some((canonical_host, _)) = self
                    .runner
                    .config()
                    .hosts
                    .get_key_value(context.host.as_str())
                else {
                    return Err(invalid_retention_provenance());
                };
                let canonical_host = canonical_host.clone();
                let capability = self
                    .runner
                    .cached_capability(&canonical_host)
                    .await
                    .ok_or_else(invalid_retention_provenance)?;
                if context.physical_root != capability.physical_root {
                    return Err(invalid_retention_provenance());
                }
                let shell = match context.shell.kind {
                    ShellName::Bash => {
                        let Some(version) = context.shell.version.as_deref() else {
                            return Err(invalid_retention_provenance());
                        };
                        if version.len() > MAX_SHELL_VERSION_BYTES || context.shell.fallback {
                            return Err(invalid_retention_provenance());
                        }
                        let ShellKind::Bash {
                            version: cached_version,
                        } = &capability.shell
                        else {
                            return Err(invalid_retention_provenance());
                        };
                        if version != cached_version {
                            return Err(invalid_retention_provenance());
                        }
                        ShellSelection {
                            shell: capability.shell.clone(),
                            fallback: false,
                        }
                    }
                    ShellName::Sh => {
                        if context.shell.version.is_some()
                            || (context.shell.fallback
                                && matches!(&capability.shell, ShellKind::Bash { .. }))
                        {
                            return Err(invalid_retention_provenance());
                        }
                        ShellSelection {
                            shell: ShellKind::PosixSh,
                            fallback: context.shell.fallback,
                        }
                    }
                    ShellName::Login => {
                        if context.shell.version.is_some() || context.shell.fallback {
                            return Err(invalid_retention_provenance());
                        }
                        ShellSelection {
                            shell: ShellKind::Login,
                            fallback: false,
                        }
                    }
                };
                StoredProvenance::Remote(OutputProvenance {
                    host: canonical_host,
                    physical_root: capability.physical_root.clone(),
                    shell,
                    helper_mode: context.helper_mode.unwrap_or(HelperMode::Shell),
                })
            }
            RetentionProvenance::Aggregate { kind, source_count } => StoredProvenance::Aggregate {
                kind: match kind {
                    AggregateKind::Hosts => StoredAggregateKind::Hosts,
                },
                source_count,
            },
        })
    }

    async fn edit_barrier(&self, host: &str, cancel: CancellationToken) -> BridgeResult<()> {
        if let Err(error) = self
            .edit_cache
            .flush_barrier(host, cancel, MAX_EDIT_BARRIER_WAIT)
            .await
        {
            let error = match error {
                edit_cache::BarrierWaitError::Cancelled => BridgeError::new(
                    ErrorCode::Cancelled,
                    "remote operation was cancelled while buffered edits were synchronizing",
                    false,
                ),
                edit_cache::BarrierWaitError::TimedOut => {
                    let mut error = BridgeError::new(
                        ErrorCode::CommandTimeout,
                        "timed out waiting for buffered edits to synchronize",
                        false,
                    );
                    error.details.host = Some(host.to_owned());
                    error.details.mutation_may_have_applied = Some(true);
                    error
                }
                edit_cache::BarrierWaitError::Edit(error) => edit_bridge_error(error),
            };
            return Err(match self.edit_backend.context_for(host).await {
                Some(context) => attach_remote_context(error, &context),
                None => error,
            });
        }
        Ok(())
    }

    async fn execute_readonly_fixed(
        &self,
        request: FixedRunRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<FixedRunResult> {
        execute_readonly_fixed(&self.runner, request, cancel).await
    }
}

async fn execute_readonly_fixed(
    runner: &SshRunner,
    request: FixedRunRequest,
    cancel: CancellationToken,
) -> BridgeResult<FixedRunResult> {
    let first = runner
        .execute_fixed_once(request.clone(), cancel.clone())
        .await?;
    let first_mismatch = protocol::capability_mismatch(&first, request.required_capabilities)
        .await
        .map_err(|error| attach_fixed_result_context(error, &request.host, &first))?;
    match first_mismatch {
        None => Ok(first),
        Some(_) => {
            runner.invalidate_capability(&request.host).await;
            let second = runner
                .execute_fixed_once(request.clone(), cancel)
                .await
                .map_err(|error| attach_fixed_result_context(error, &request.host, &first))?;
            let second_mismatch =
                protocol::capability_mismatch(&second, request.required_capabilities)
                    .await
                    .map_err(|error| attach_fixed_result_context(error, &request.host, &second))?;
            match second_mismatch {
                None => Ok(second),
                Some(_) => Err(attach_fixed_result_context(
                    BridgeError::new(
                        ErrorCode::RemoteCapabilityMissing,
                        "remote read capability remained unavailable after reprobe",
                        false,
                    ),
                    &request.host,
                    &second,
                )),
            }
        }
    }
}

#[derive(Debug)]
struct ResolvedList {
    host: String,
    path: RemotePath,
    depth: u32,
    include_hidden: bool,
    max_entries: usize,
}

#[derive(Debug)]
struct ResolvedStat {
    host: String,
    paths: Vec<RemotePath>,
}

#[derive(Debug)]
struct ResolvedRead {
    host: String,
    paths: Vec<RemotePath>,
    start_line: u64,
    max_lines: u64,
    max_bytes: usize,
}

#[derive(Debug)]
struct ResolvedSearch {
    host: String,
    query: String,
    path: RemotePath,
    globs: Vec<String>,
    max_results: usize,
    binary: bool,
}

fn resolve_list(config: &Config, request: ListRequest) -> BridgeResult<ResolvedList> {
    config.require_discovered_alias(&request.host)?;
    let limits = config.limits();
    let requested = request.path.as_deref().ok_or_else(absolute_path_required)?;
    validate_path(requested)?;
    let path = resolve_path(requested)?;
    let depth = request.depth.unwrap_or(DEFAULT_LIST_DEPTH);
    if !(1..=MAX_LIST_DEPTH).contains(&depth) {
        return Err(BridgeError::invalid_argument(
            "list depth must be between 1 and 32",
        ));
    }
    let max_entries = request.max_entries.unwrap_or(DEFAULT_LIST_ENTRIES);
    if !(1..=MAX_LIST_ENTRIES).contains(&max_entries) {
        return Err(BridgeError::invalid_argument(
            "list max_entries must be between 1 and 10000",
        ));
    }
    validate_frame(limits, [path.as_str().len()])?;
    Ok(ResolvedList {
        host: request.host,
        path,
        depth,
        include_hidden: request.include_hidden.unwrap_or(false),
        max_entries,
    })
}

fn resolve_stat(config: &Config, request: StatRequest) -> BridgeResult<ResolvedStat> {
    config.require_discovered_alias(&request.host)?;
    let limits = config.limits();
    if request.paths.is_empty() || request.paths.len() > MAX_STAT_PATHS {
        return Err(BridgeError::invalid_argument(
            "stat paths must contain between 1 and 256 items",
        ));
    }
    let paths = resolve_paths(&request.paths)?;
    validate_frame(limits, paths.iter().map(|path| path.as_str().len() + 1))?;
    Ok(ResolvedStat {
        host: request.host,
        paths,
    })
}

fn resolve_read(config: &Config, request: ReadRequest) -> BridgeResult<ResolvedRead> {
    config.require_discovered_alias(&request.host)?;
    let limits = config.limits();
    if request.paths.is_empty() || request.paths.len() > MAX_READ_PATHS {
        return Err(BridgeError::invalid_argument(
            "read paths must contain between 1 and 32 items",
        ));
    }
    let paths = resolve_paths(&request.paths)?;
    let start_line = request.start_line.unwrap_or(DEFAULT_START_LINE);
    let max_lines = request.max_lines.unwrap_or(DEFAULT_MAX_LINES);
    if start_line == 0 {
        return Err(BridgeError::invalid_argument(
            "read start_line must be positive",
        ));
    }
    if !(1..=MAX_LINES).contains(&max_lines) {
        return Err(BridgeError::invalid_argument(
            "read max_lines must be between 1 and 100000",
        ));
    }
    start_line
        .checked_add(max_lines - 1)
        .ok_or_else(|| BridgeError::invalid_argument("read line range overflows"))?;
    let max_bytes = request.max_bytes.unwrap_or(limits.read_chunk_bytes);
    if max_bytes == 0 || max_bytes > limits.max_read_bytes {
        return Err(BridgeError::invalid_argument(
            "read max_bytes exceeds the configured limit",
        ));
    }
    validate_frame(limits, paths.iter().map(|path| path.as_str().len() + 1))?;
    Ok(ResolvedRead {
        host: request.host,
        paths,
        start_line,
        max_lines,
        max_bytes,
    })
}

fn resolve_search(config: &Config, request: SearchRequest) -> BridgeResult<ResolvedSearch> {
    config.require_discovered_alias(&request.host)?;
    let limits = config.limits();
    if request.query.is_empty()
        || request.query.as_bytes().contains(&0)
        || request.query.contains(['\r', '\n'])
    {
        return Err(BridgeError::invalid_argument(
            "search query must be non-empty and single-line",
        ));
    }
    if request.query.len() > MAX_QUERY_BYTES {
        return Err(request_too_large());
    }
    if request.globs.len() > MAX_GLOBS {
        return Err(BridgeError::invalid_argument(
            "search accepts at most 128 globs",
        ));
    }
    for glob in &request.globs {
        validate_glob(glob)?;
    }
    let requested = request.path.as_deref().ok_or_else(absolute_path_required)?;
    validate_path(requested)?;
    let path = resolve_path(requested)?;
    let max_results = request.max_results.unwrap_or(DEFAULT_SEARCH_RESULTS);
    if !(1..=MAX_SEARCH_RESULTS).contains(&max_results) {
        return Err(BridgeError::invalid_argument(
            "search max_results must be between 1 and 10000",
        ));
    }
    validate_frame(
        limits,
        std::iter::once(request.query.len())
            .chain(std::iter::once(path.as_str().len()))
            .chain(request.globs.iter().map(|glob| glob.len() + 1)),
    )?;
    Ok(ResolvedSearch {
        host: request.host,
        query: request.query,
        path,
        globs: request.globs,
        max_results,
        binary: request.binary.unwrap_or(false),
    })
}

fn resolve_paths(values: &[String]) -> BridgeResult<Vec<RemotePath>> {
    values
        .iter()
        .map(|value| {
            validate_path(value)?;
            resolve_path(value)
        })
        .collect()
}

fn resolve_path(requested: &str) -> BridgeResult<RemotePath> {
    RemotePath::absolute(requested)
}

fn absolute_path_required() -> BridgeError {
    BridgeError::new(
        ErrorCode::RemoteAbsolutePathRequired,
        "remote path or cwd must be provided as an absolute path",
        false,
    )
}

fn validate_path(path: &str) -> BridgeResult<()> {
    if path.len() > MAX_INPUT_PATH_BYTES {
        return Err(request_too_large());
    }
    if path.as_bytes().contains(&0) {
        return Err(BridgeError::invalid_argument(
            "NUL is not valid in a remote path",
        ));
    }
    Ok(())
}

fn validate_glob(glob: &str) -> BridgeResult<()> {
    if glob.is_empty() || glob.len() > MAX_GLOB_BYTES {
        return Err(if glob.len() > MAX_GLOB_BYTES {
            request_too_large()
        } else {
            BridgeError::invalid_argument("search glob must not be empty")
        });
    }
    if glob.as_bytes().contains(&0)
        || glob.starts_with('/')
        || glob.starts_with('!')
        || glob.split('/').any(|part| part == "..")
    {
        return Err(BridgeError::invalid_argument(
            "search glob must be a positive root-relative pattern",
        ));
    }
    compile_glob(glob)?;
    Ok(())
}

fn compile_glob(glob: &str) -> BridgeResult<globset::Glob> {
    globset::GlobBuilder::new(glob)
        .literal_separator(true)
        .build()
        .map_err(|_| BridgeError::invalid_argument("search glob is invalid"))
}

fn validate_frame(
    limits: EffectiveLimits,
    lengths: impl IntoIterator<Item = usize>,
) -> BridgeResult<()> {
    let total = lengths.into_iter().try_fold(0usize, |total, length| {
        total.checked_add(length).ok_or_else(request_too_large)
    })?;
    if total > limits.max_frame_bytes {
        return Err(request_too_large());
    }
    Ok(())
}

fn request_too_large() -> BridgeError {
    BridgeError::new(
        ErrorCode::RequestTooLarge,
        "request exceeds the configured frame limit",
        false,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListRequest {
    pub host: String,
    pub path: Option<String>,
    pub depth: Option<u32>,
    pub include_hidden: Option<bool>,
    pub max_entries: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatRequest {
    pub host: String,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRequest {
    pub host: String,
    pub paths: Vec<String>,
    pub start_line: Option<u64>,
    pub max_lines: Option<u64>,
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRequest {
    pub host: String,
    pub query: String,
    pub path: Option<String>,
    pub globs: Vec<String>,
    pub max_results: Option<usize>,
    pub binary: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteEncoding {
    Utf8,
    Base64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunShell {
    Bash,
    Sh,
    Login,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunStdin {
    pub encoding: WriteEncoding,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRunRequest {
    pub host: String,
    pub command: String,
    pub cwd: Option<String>,
    pub shell: RunShell,
    pub timeout_ms: Option<u64>,
    pub stdin: Option<RunStdin>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteMode {
    Create,
    Replace { expected_sha256: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteRequest {
    pub host: String,
    pub path: String,
    pub content: String,
    pub encoding: WriteEncoding,
    pub mode: WriteMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyPatchRequest {
    pub host: String,
    pub patch: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditStatusRequest {
    pub host: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncEditsRequest {
    pub host: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscardEditsRequest {
    pub host: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GuardedDeleteRequest {
    pub host: String,
    pub path: String,
    pub expected_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputReadRequest {
    pub output_ref: String,
    pub stream: StreamKind,
    pub offset: u64,
    pub max_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoteContext {
    pub remote: bool,
    pub host: String,
    pub physical_root: String,
    pub shell: ShellMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub helper_mode: Option<HelperMode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AggregateKind {
    Hosts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum RetentionProvenance {
    Remote(RemoteContext),
    Aggregate {
        kind: AggregateKind,
        source_count: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShellMetadata {
    pub kind: ShellName,
    pub version: Option<String>,
    pub fallback: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellName {
    Bash,
    Sh,
    Login,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostInfo {
    pub host: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ValueEncoding {
    Utf8,
    Base64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EncodedValue {
    pub encoding: ValueEncoding,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EncodedOutputPreview {
    pub head: EncodedValue,
    pub tail: EncodedValue,
    pub raw_bytes: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoteRunResult {
    #[serde(flatten)]
    pub context: RemoteContext,
    pub exit_status: i32,
    pub elapsed_ms: u64,
    pub stdout: EncodedOutputPreview,
    pub stderr: EncodedOutputPreview,
    pub aggregate_bytes: u64,
    pub output_ref: Option<String>,
    pub remote_process_may_continue: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteFileKind {
    File,
    Directory,
    Symlink,
    BlockDevice,
    CharacterDevice,
    Fifo,
    Socket,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoteMetadata {
    pub kind: RemoteFileKind,
    pub size: u64,
    pub mode: u32,
    pub mtime_seconds: i64,
    pub mtime_nanoseconds: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EntryErrorCode {
    ReadConflict,
    NotFound,
    PermissionDenied,
    InvalidArgument,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntryError {
    pub code: EntryErrorCode,
    pub message: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostsResult {
    pub hosts: Vec<HostInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListEntry {
    pub actual_path: EncodedValue,
    pub relative_path: EncodedValue,
    pub metadata: RemoteMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListResult {
    #[serde(flatten)]
    pub context: RemoteContext,
    pub actual_path: EncodedValue,
    pub relative_path: EncodedValue,
    pub entries: Vec<ListEntry>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum StatEntry {
    Success {
        actual_path: EncodedValue,
        relative_path: EncodedValue,
        metadata: RemoteMetadata,
    },
    Error {
        actual_path: EncodedValue,
        relative_path: EncodedValue,
        error: EntryError,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatResult {
    #[serde(flatten)]
    pub context: RemoteContext,
    pub entries: Vec<StatEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ReadEntry {
    Success {
        actual_path: EncodedValue,
        relative_path: EncodedValue,
        content: EncodedValue,
        raw_bytes: u64,
        sha256: String,
        truncated_before: bool,
        truncated_after: bool,
        truncated: bool,
    },
    Error {
        actual_path: EncodedValue,
        relative_path: EncodedValue,
        error: EntryError,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReadResult {
    #[serde(flatten)]
    pub context: RemoteContext,
    pub files: Vec<ReadEntry>,
    pub returned_raw_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SearchEngine {
    Native,
    Rg,
    Grep,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SearchMatch {
    pub actual_path: EncodedValue,
    pub relative_path: EncodedValue,
    pub line: u64,
    pub column: u64,
    pub content: EncodedValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SearchResult {
    #[serde(flatten)]
    pub context: RemoteContext,
    pub engine: SearchEngine,
    pub matches: Vec<SearchMatch>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OutputReadResult {
    pub provenance: RetentionProvenance,
    pub stream: StreamKind,
    pub offset: u64,
    pub next_offset: u64,
    pub eof: bool,
    pub data: EncodedValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WriteOperation {
    Create,
    Replace,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WriteResult {
    #[serde(flatten)]
    pub context: RemoteContext,
    pub actual_path: EncodedValue,
    pub relative_path: EncodedValue,
    pub operation: WriteOperation,
    pub raw_bytes: u64,
    pub sha256: String,
    pub mode: u32,
    pub temporary_cleanup_confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApplyPatchResult {
    #[serde(flatten)]
    pub context: RemoteContext,
    pub changed_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EditStatusResult {
    pub remote: bool,
    pub host: String,
    pub pending_paths: Vec<String>,
    pub outcome_unknown_paths: Vec<String>,
    pub pending_payload_bytes: usize,
    pub cached_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SyncEditsResult {
    pub remote: bool,
    pub host: String,
    pub pending_paths: Vec<String>,
    pub outcome_unknown_paths: Vec<String>,
    pub pending_payload_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiscardEditsResult {
    pub remote: bool,
    pub host: String,
    pub discarded_paths: Vec<String>,
    pub discarded_payload_bytes: usize,
    pub had_outcome_unknown: bool,
    pub pending_paths: Vec<String>,
    pub outcome_unknown_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GuardedDeleteResult {
    pub actual_path: EncodedValue,
    pub relative_path: EncodedValue,
    pub deleted_sha256: String,
    pub absence_confirmed: bool,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::config::{CONFIG_VERSION, Config, HostLimitOverrides, HostProfile, Limits};

    fn config() -> Config {
        Config {
            version: CONFIG_VERSION,
            limits: Limits::default(),
            hosts: BTreeMap::from([(
                "dev".to_owned(),
                HostProfile {
                    root: "/srv/root".to_owned(),
                    description: None,
                    read_only: true,
                    limits: HostLimitOverrides::default(),
                },
            )]),
        }
    }

    #[test]
    fn request_validation_rejects_query_lines_and_aggregate_stat_before_io() {
        let config = config();
        for query in ["", "a\nb", "a\rb"] {
            let error = resolve_search(
                &config,
                SearchRequest {
                    host: "dev".into(),
                    query: query.into(),
                    path: Some("/".into()),
                    globs: vec![],
                    max_results: None,
                    binary: None,
                },
            )
            .unwrap_err();
            assert_eq!(error.code, ErrorCode::InvalidArgument);
        }
        let paths = (0..256)
            .map(|index| format!("/{}-{index}", "x".repeat(40_000)))
            .collect();
        let error = resolve_stat(
            &config,
            StatRequest {
                host: "dev".into(),
                paths,
            },
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::RequestTooLarge);
    }

    #[test]
    fn request_validation_applies_defaults_and_checked_ranges() {
        let list = resolve_list(
            &config(),
            ListRequest {
                host: "dev".into(),
                path: Some("/".into()),
                depth: None,
                include_hidden: None,
                max_entries: None,
            },
        )
        .unwrap();
        assert_eq!(
            (list.depth, list.max_entries, list.include_hidden),
            (1, 1_000, false)
        );
        let read = resolve_read(
            &config(),
            ReadRequest {
                host: "dev".into(),
                paths: vec!["/a".into()],
                start_line: None,
                max_lines: None,
                max_bytes: None,
            },
        )
        .unwrap();
        assert_eq!((read.start_line, read.max_lines), (1, 2_000));
        let error = resolve_read(
            &config(),
            ReadRequest {
                host: "dev".into(),
                paths: vec!["/a".into()],
                start_line: Some(u64::MAX),
                max_lines: Some(2),
                max_bytes: None,
            },
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }
}
