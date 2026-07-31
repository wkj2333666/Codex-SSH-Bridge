use std::sync::Arc;

use codex_ssh_bridge::cli;
use codex_ssh_bridge::config::Config;
use codex_ssh_bridge::mcp::McpServer;
use codex_ssh_bridge::mcp::tools::RemoteMcpTools;
use codex_ssh_bridge::output::OutputStore;
use codex_ssh_bridge::remote::RemoteBridge;
use codex_ssh_bridge::ssh::{RuntimePaths, SshRunner};
use codex_ssh_bridge::{BridgeResult, ErrorCode};

const USAGE: &str = "usage: codex-ssh-bridge mcp";
const FATAL_PREFIX: &str = "codex-ssh-bridge fatal: ";

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() == 1 && arguments[0] == std::ffi::OsStr::new("mcp") {
        if let Err(error) = run_mcp().await {
            eprintln!("{FATAL_PREFIX}{}", stable_error_code(error.code));
            std::process::exit(1);
        }
        return;
    }
    if arguments.is_empty()
        || arguments[0] == std::ffi::OsStr::new("mcp")
        || !cli::known_human_mode(&arguments[0])
    {
        eprintln!("{USAGE}");
        std::process::exit(2);
    }
    let parsed = match cli::parse(arguments) {
        Ok(parsed) => parsed,
        Err(error) => {
            let exit_code = error.exit_code();
            let _ = error.print();
            std::process::exit(exit_code);
        }
    };
    if let Err(error) = cli::run(parsed).await {
        eprintln!("{FATAL_PREFIX}{}", stable_error_code(error.code));
        std::process::exit(1);
    }
}

async fn run_mcp() -> BridgeResult<()> {
    let loaded = Config::load_default()?;
    let max_frame_bytes = loaded.config.limits.max_frame_bytes;
    let global_spool_quota_bytes = loaded.config.limits.global_spool_quota_bytes;
    let retention_serialization_jobs = loaded.config.limits.retention_serialization_jobs;
    let config = Arc::new(loaded.config);
    let runtime = RuntimePaths::discover()?;
    let output_store = Arc::new(OutputStore::with_limits(
        &runtime,
        global_spool_quota_bytes,
        retention_serialization_jobs,
    )?);
    let runner = Arc::new(SshRunner::new(Arc::clone(&config), runtime, output_store)?);
    let bridge = Arc::new(RemoteBridge::new(runner));
    let tools = Arc::new(RemoteMcpTools::new(bridge));
    let server = McpServer::new(tools, max_frame_bytes)?;
    server.serve(tokio::io::stdin(), tokio::io::stdout()).await
}

const fn stable_error_code(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::HostKeyUnknown => "HOST_KEY_UNKNOWN",
        ErrorCode::AuthRequired => "AUTH_REQUIRED",
        ErrorCode::ConnectTimeout => "CONNECT_TIMEOUT",
        ErrorCode::RemoteCapabilityMissing => "REMOTE_CAPABILITY_MISSING",
        ErrorCode::RemoteAbsolutePathRequired => "REMOTE_ABSOLUTE_PATH_REQUIRED",
        ErrorCode::PathOutsideRoot => "PATH_OUTSIDE_ROOT",
        ErrorCode::ReadOnlyHost => "READ_ONLY_HOST",
        ErrorCode::WriteConflict => "WRITE_CONFLICT",
        ErrorCode::ReadConflict => "READ_CONFLICT",
        ErrorCode::NotFound => "NOT_FOUND",
        ErrorCode::PermissionDenied => "PERMISSION_DENIED",
        ErrorCode::NotDirectory => "NOT_DIRECTORY",
        ErrorCode::MutationOutcomeUnknown => "MUTATION_OUTCOME_UNKNOWN",
        ErrorCode::JobStartOutcomeUnknown => "JOB_START_OUTCOME_UNKNOWN",
        ErrorCode::JobCancelOutcomeUnknown => "JOB_CANCEL_OUTCOME_UNKNOWN",
        ErrorCode::JobStateInvalid => "JOB_STATE_INVALID",
        ErrorCode::JobExpired => "JOB_EXPIRED",
        ErrorCode::OutputLimit => "OUTPUT_LIMIT",
        ErrorCode::RequestTooLarge => "REQUEST_TOO_LARGE",
        ErrorCode::ProtocolError => "PROTOCOL_ERROR",
        ErrorCode::Cancelled => "CANCELLED",
        ErrorCode::CommandTimeout => "COMMAND_TIMEOUT",
        ErrorCode::RemoteExit => "REMOTE_EXIT",
        ErrorCode::InvalidConfig => "INVALID_CONFIG",
        ErrorCode::InvalidArgument => "INVALID_ARGUMENT",
        ErrorCode::Io => "IO",
    }
}
