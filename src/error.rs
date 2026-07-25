use std::fmt;

use serde::Serialize;

pub type BridgeResult<T> = Result<T, BridgeError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    HostKeyUnknown,
    AuthRequired,
    ConnectTimeout,
    RemoteCapabilityMissing,
    RemoteAbsolutePathRequired,
    PathOutsideRoot,
    ReadOnlyHost,
    WriteConflict,
    ReadConflict,
    NotFound,
    PermissionDenied,
    NotDirectory,
    MutationOutcomeUnknown,
    OutputLimit,
    RequestTooLarge,
    ProtocolError,
    Cancelled,
    CommandTimeout,
    RemoteExit,
    InvalidConfig,
    InvalidArgument,
    Io,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorShellMetadata {
    pub kind: String,
    pub version: Option<String>,
    pub fallback: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ErrorDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell: Option<ErrorShellMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub physical_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_status: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_shell: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_shells: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_process_may_continue: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_seen: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mutation_may_have_applied: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed_paths: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_changed_paths: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome_unknown_paths: Option<Vec<String>>,
}

pub fn attach_available_remote_context(
    error: &mut BridgeError,
    host: Option<&str>,
    physical_root: Option<&str>,
    shell: Option<&ErrorShellMetadata>,
) {
    if error.details.host.is_none() {
        error.details.host = host.map(str::to_owned);
    }
    if error.details.physical_root.is_none() {
        error.details.physical_root = physical_root.map(str::to_owned);
    }
    if error.details.shell.is_none() {
        error.details.shell = shell.cloned();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BridgeError {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
    pub details: ErrorDetails,
}

impl BridgeError {
    pub fn new(code: ErrorCode, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            code,
            message: message.into(),
            retryable,
            details: ErrorDetails::default(),
        }
    }

    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArgument, message, false)
    }

    pub fn invalid_config(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidConfig, message, false)
    }

    pub fn io(error: impl fmt::Display) -> Self {
        Self::new(ErrorCode::Io, error.to_string(), false)
    }

    pub(crate) fn read_conflict() -> Self {
        Self::new(
            ErrorCode::ReadConflict,
            "remote file changed while being read",
            false,
        )
    }

    pub(crate) fn not_found() -> Self {
        Self::new(ErrorCode::NotFound, "remote path was not found", false)
    }

    pub(crate) fn permission_denied() -> Self {
        Self::new(
            ErrorCode::PermissionDenied,
            "remote path permission was denied",
            false,
        )
    }

    pub(crate) fn not_directory() -> Self {
        Self::new(
            ErrorCode::NotDirectory,
            "remote path is not a directory",
            false,
        )
    }

    pub(crate) fn mutation_outcome_unknown() -> Self {
        let mut error = Self::new(
            ErrorCode::MutationOutcomeUnknown,
            "remote mutation outcome could not be confirmed",
            false,
        );
        error.details.mutation_may_have_applied = Some(true);
        error
    }
}

impl fmt::Display for BridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

impl std::error::Error for BridgeError {}

impl From<std::io::Error> for BridgeError {
    fn from(error: std::io::Error) -> Self {
        Self::io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::{BridgeError, ErrorCode};

    #[test]
    fn mutation_outcome_unknown_constructor_is_closed_and_non_retryable() {
        let error = BridgeError::mutation_outcome_unknown();
        assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
        assert_eq!(
            error.message,
            "remote mutation outcome could not be confirmed"
        );
        assert!(!error.retryable);
        assert_eq!(error.details.mutation_may_have_applied, Some(true));
    }
}
