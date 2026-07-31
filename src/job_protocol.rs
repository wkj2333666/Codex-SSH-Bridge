use std::fmt;

use rand::RngCore as _;
use serde::{Deserialize, Serialize};

pub const JOB_RECORD_VERSION: u32 = 1;
pub const JOB_ID_HEX_BYTES: usize = 32;
pub const MAX_JOB_LABEL_BYTES: usize = 256;
pub const DEFAULT_JOB_LOG_PAGE_BYTES: usize = 256 * 1024;
pub const MAX_JOB_LOG_PAGE_BYTES: usize = 1024 * 1024;
pub const MAX_JOB_LIST_ENTRIES: usize = 1_000;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JobId(String);

impl JobId {
    pub fn generate() -> Self {
        let mut bytes = [0_u8; 16];
        rand::rng().fill_bytes(&mut bytes);
        let mut encoded = String::with_capacity(JOB_ID_HEX_BYTES);
        for byte in bytes {
            use fmt::Write as _;
            write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
        }
        Self(encoded)
    }

    pub fn parse(value: &str) -> Result<Self, JobProtocolError> {
        if value.len() != JOB_ID_HEX_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(JobProtocolError::InvalidJobId);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Starting,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
    Lost,
}

impl JobState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::TimedOut | Self::Lost
        )
    }

    pub fn can_transition_to(self, next: Self) -> bool {
        match self {
            Self::Starting => matches!(next, Self::Running | Self::Lost),
            Self::Running => next.is_terminal(),
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::TimedOut | Self::Lost => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum JobShell {
    Bash,
    Sh,
    Login { path: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: i32,
    pub start_ticks: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRequestRecord {
    pub version: u32,
    pub job_id: JobId,
    pub shell: JobShell,
    pub cwd: String,
    pub command: String,
    pub stdin_base64: String,
    pub timeout_ms: Option<u64>,
    pub label: Option<String>,
    pub max_output_bytes: u64,
    pub created_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobStateRecord {
    pub version: u32,
    pub job_id: JobId,
    pub state: JobState,
    pub boot_id: String,
    pub runner: Option<ProcessIdentity>,
    pub command_group: Option<ProcessIdentity>,
    pub created_unix_ms: u64,
    pub started_unix_ms: Option<u64>,
    pub finished_unix_ms: Option<u64>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout_retained_bytes: u64,
    pub stdout_observed_bytes: u64,
    pub stderr_retained_bytes: u64,
    pub stderr_observed_bytes: u64,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobLogsRequest {
    pub job_id: JobId,
    pub stdout_offset: u64,
    pub stderr_offset: u64,
    pub max_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobLogEncoding {
    Utf8,
    Base64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobLogPage {
    pub encoding: JobLogEncoding,
    pub value: String,
    pub next_offset: u64,
    pub eof: bool,
    pub retained_bytes: u64,
    pub observed_bytes: u64,
    pub truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobLogsResponse {
    pub job_id: JobId,
    pub state: JobState,
    pub stdout: JobLogPage,
    pub stderr: JobLogPage,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobSummary {
    pub job_id: JobId,
    pub label: Option<String>,
    pub state: JobState,
    pub cwd: String,
    pub created_unix_ms: u64,
    pub started_unix_ms: Option<u64>,
    pub finished_unix_ms: Option<u64>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum JobControlRequest {
    Start(JobRequestRecord),
    Status { job_id: JobId },
    Logs(JobLogsRequest),
    Cancel { job_id: JobId },
    List { max_jobs: usize },
    Delete { job_id: JobId },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum JobControlResponse {
    Started(JobStateRecord),
    Status(JobStateRecord),
    Logs(JobLogsResponse),
    Cancelled(JobStateRecord),
    Listed(Vec<JobSummary>),
    Deleted { job_id: JobId },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobProtocolError {
    InvalidJobId,
}

impl fmt::Display for JobProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJobId => formatter.write_str("invalid remote job id"),
        }
    }
}

impl std::error::Error for JobProtocolError {}
