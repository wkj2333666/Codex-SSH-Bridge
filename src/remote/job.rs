use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::error::{BridgeError, BridgeResult, ErrorCode};
use crate::job_protocol::{
    JOB_RECORD_VERSION, JobControlRequest, JobControlResponse, JobId, JobLogsRequest,
    JobLogsResponse, JobRequestRecord, JobShell, JobState, JobStateRecord, JobSummary,
    MAX_JOB_LABEL_BYTES, MAX_JOB_LIST_ENTRIES, MAX_JOB_LOG_PAGE_BYTES,
};

use super::{RemoteBridge, RunShell, RunStdin, run};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteJobStartRequest {
    pub host: String,
    pub command: String,
    pub cwd: String,
    pub shell: RunShell,
    pub stdin: Option<RunStdin>,
    pub timeout_ms: Option<u64>,
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteJobIdRequest {
    pub host: String,
    pub job_id: JobId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteJobLogsRequest {
    pub host: String,
    pub job_id: JobId,
    pub stdout_offset: u64,
    pub stderr_offset: u64,
    pub max_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteJobListRequest {
    pub host: String,
    pub max_jobs: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoteJobStartResult {
    pub host: String,
    pub job_id: JobId,
    pub state: JobState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoteJobStatusResult {
    pub host: String,
    pub record: JobStateRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoteJobLogsResult {
    pub host: String,
    pub logs: JobLogsResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoteJobListResult {
    pub host: String,
    pub jobs: Vec<JobSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoteJobDeleteResult {
    pub host: String,
    pub job_id: JobId,
}

pub(super) async fn start(
    bridge: &RemoteBridge,
    request: RemoteJobStartRequest,
    cancel: CancellationToken,
) -> BridgeResult<RemoteJobStartResult> {
    let (host, record) = prepare_start(bridge, request)?;
    let job_id = record.job_id.clone();
    bridge.edit_barrier(&host, cancel.clone()).await?;
    let response = match bridge
        .runner
        .execute_job(host.clone(), JobControlRequest::Start(record), cancel)
        .await
    {
        Ok(response) => response,
        Err(error) => {
            let error = uncertain(error, ErrorCode::JobStartOutcomeUnknown, &job_id);
            if error.code == ErrorCode::JobStartOutcomeUnknown {
                bridge.edit_cache.invalidate_clean_host(&host).await;
            }
            return Err(error);
        }
    };
    bridge.edit_cache.invalidate_clean_host(&host).await;
    let JobControlResponse::Started(record) = response else {
        return Err(response_mismatch(&host, &job_id));
    };
    Ok(RemoteJobStartResult {
        host,
        job_id,
        state: record.state,
    })
}

pub(super) async fn status(
    bridge: &RemoteBridge,
    request: RemoteJobIdRequest,
    cancel: CancellationToken,
) -> BridgeResult<RemoteJobStatusResult> {
    bridge
        .runner
        .config()
        .require_discovered_alias(&request.host)?;
    let response = bridge
        .runner
        .execute_job(
            request.host.clone(),
            JobControlRequest::Status {
                job_id: request.job_id.clone(),
            },
            cancel,
        )
        .await?;
    let JobControlResponse::Status(record) = response else {
        return Err(response_mismatch(&request.host, &request.job_id));
    };
    Ok(RemoteJobStatusResult {
        host: request.host,
        record,
    })
}

pub(super) async fn logs(
    bridge: &RemoteBridge,
    request: RemoteJobLogsRequest,
    cancel: CancellationToken,
) -> BridgeResult<RemoteJobLogsResult> {
    bridge
        .runner
        .config()
        .require_discovered_alias(&request.host)?;
    if request.max_bytes == 0 || request.max_bytes > MAX_JOB_LOG_PAGE_BYTES {
        return Err(BridgeError::invalid_argument(
            "remote Job log page size is invalid",
        ));
    }
    let response = bridge
        .runner
        .execute_job(
            request.host.clone(),
            JobControlRequest::Logs(JobLogsRequest {
                job_id: request.job_id.clone(),
                stdout_offset: request.stdout_offset,
                stderr_offset: request.stderr_offset,
                max_bytes: request.max_bytes,
            }),
            cancel,
        )
        .await?;
    let JobControlResponse::Logs(logs) = response else {
        return Err(response_mismatch(&request.host, &request.job_id));
    };
    Ok(RemoteJobLogsResult {
        host: request.host,
        logs,
    })
}

pub(super) async fn cancel(
    bridge: &RemoteBridge,
    request: RemoteJobIdRequest,
    cancel: CancellationToken,
) -> BridgeResult<RemoteJobStatusResult> {
    bridge
        .runner
        .config()
        .require_discovered_alias(&request.host)?;
    let response = bridge
        .runner
        .execute_job(
            request.host.clone(),
            JobControlRequest::Cancel {
                job_id: request.job_id.clone(),
            },
            cancel,
        )
        .await
        .map_err(|error| uncertain(error, ErrorCode::JobCancelOutcomeUnknown, &request.job_id))?;
    let JobControlResponse::Cancelled(record) = response else {
        return Err(response_mismatch(&request.host, &request.job_id));
    };
    Ok(RemoteJobStatusResult {
        host: request.host,
        record,
    })
}

pub(super) async fn list(
    bridge: &RemoteBridge,
    request: RemoteJobListRequest,
    cancel: CancellationToken,
) -> BridgeResult<RemoteJobListResult> {
    bridge
        .runner
        .config()
        .require_discovered_alias(&request.host)?;
    if request.max_jobs == 0 || request.max_jobs > MAX_JOB_LIST_ENTRIES {
        return Err(BridgeError::invalid_argument(
            "remote Job list size is invalid",
        ));
    }
    let response = bridge
        .runner
        .execute_job(
            request.host.clone(),
            JobControlRequest::List {
                max_jobs: request.max_jobs,
            },
            cancel,
        )
        .await?;
    let JobControlResponse::Listed(jobs) = response else {
        return Err(BridgeError::new(
            ErrorCode::ProtocolError,
            "remote Job list response was invalid",
            false,
        ));
    };
    Ok(RemoteJobListResult {
        host: request.host,
        jobs,
    })
}

pub(super) async fn delete(
    bridge: &RemoteBridge,
    request: RemoteJobIdRequest,
    cancel: CancellationToken,
) -> BridgeResult<RemoteJobDeleteResult> {
    bridge
        .runner
        .config()
        .require_discovered_alias(&request.host)?;
    let response = bridge
        .runner
        .execute_job(
            request.host.clone(),
            JobControlRequest::Delete {
                job_id: request.job_id.clone(),
            },
            cancel,
        )
        .await?;
    let JobControlResponse::Deleted { job_id } = response else {
        return Err(response_mismatch(&request.host, &request.job_id));
    };
    Ok(RemoteJobDeleteResult {
        host: request.host,
        job_id,
    })
}

fn prepare_start(
    bridge: &RemoteBridge,
    request: RemoteJobStartRequest,
) -> BridgeResult<(String, JobRequestRecord)> {
    let resolved = bridge.runner.config().host(&request.host)?;
    if request.command.is_empty() || request.command.as_bytes().contains(&0) {
        return Err(BridgeError::invalid_argument(
            "remote Job command must be nonempty and contain no NUL",
        ));
    }
    super::validate_path(&request.cwd)?;
    let cwd = super::resolve_path(&request.cwd)?;
    if request.timeout_ms == Some(0) {
        return Err(BridgeError::invalid_argument(
            "remote Job timeout must be positive",
        ));
    }
    if request
        .label
        .as_ref()
        .is_some_and(|label| label.len() > MAX_JOB_LABEL_BYTES || label.as_bytes().contains(&0))
    {
        return Err(BridgeError::invalid_argument("remote Job label is invalid"));
    }
    let stdin = run::decode_stdin(request.stdin, resolved.limits.max_write_bytes)?
        .map_or_else(String::new, |value| STANDARD.encode(value));
    let shell = match request.shell {
        RunShell::Bash => JobShell::Bash,
        RunShell::Sh => JobShell::Sh,
        RunShell::Login => JobShell::Login {
            path: String::new(),
        },
    };
    Ok((
        request.host,
        JobRequestRecord {
            version: JOB_RECORD_VERSION,
            job_id: JobId::generate(),
            shell,
            cwd: cwd.as_str().to_owned(),
            command: request.command,
            stdin_base64: stdin,
            timeout_ms: request.timeout_ms,
            label: request.label,
            max_output_bytes: resolved.limits.max_output_bytes,
            created_unix_ms: now_ms()?,
        },
    ))
}

fn now_ms() -> BridgeResult<u64> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(BridgeError::io)?
        .as_millis();
    u64::try_from(value).map_err(|_| BridgeError::invalid_argument("system time is too large"))
}

fn uncertain(mut source: BridgeError, code: ErrorCode, job_id: &JobId) -> BridgeError {
    if source.details.remote_process_may_continue != Some(true) {
        return source;
    }
    source.code = code;
    source.message = match code {
        ErrorCode::JobStartOutcomeUnknown => {
            "remote Job start outcome could not be confirmed".to_owned()
        }
        ErrorCode::JobCancelOutcomeUnknown => {
            "remote Job cancellation outcome could not be confirmed".to_owned()
        }
        _ => source.message,
    };
    source.retryable = false;
    source.details.job_id = Some(job_id.to_string());
    source
}

fn response_mismatch(host: &str, job_id: &JobId) -> BridgeError {
    let mut error = BridgeError::new(
        ErrorCode::ProtocolError,
        "remote Job control response was invalid",
        false,
    );
    error.details.host = Some(host.to_owned());
    error.details.job_id = Some(job_id.to_string());
    error
}
