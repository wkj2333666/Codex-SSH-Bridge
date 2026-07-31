use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use tokio_util::sync::CancellationToken;

use crate::capability::{ShellKind, ShellRequest};
use crate::error::{BridgeError, BridgeResult, ErrorCode};
use crate::output::{CapturedOutput, OutputPreview};

use super::{
    EncodedOutputPreview, POSIX_SH_WARNING, RemoteBridge, RemoteRunRequest, RemoteRunResult,
    RunShell, RunStdin, WriteEncoding, protocol,
};

pub(super) async fn run(
    bridge: &RemoteBridge,
    request: RemoteRunRequest,
    cancel: CancellationToken,
) -> BridgeResult<RemoteRunResult> {
    bridge
        .runner
        .config()
        .require_discovered_alias(&request.host)?;
    let limits = bridge.runner.config().limits();
    if request.command.is_empty() || request.command.as_bytes().contains(&0) {
        return Err(BridgeError::invalid_argument(
            "remote command must be nonempty and contain no NUL",
        ));
    }

    let requested_cwd = request.cwd.as_deref().ok_or_else(|| {
        BridgeError::new(
            ErrorCode::RemoteAbsolutePathRequired,
            "remote cwd must be provided as an absolute path",
            false,
        )
    })?;
    super::validate_path(requested_cwd)?;
    let cwd = super::resolve_path(requested_cwd)?;
    let stdin = decode_stdin(request.stdin, limits.max_write_bytes)?;
    let timeout_ms = request.timeout_ms.unwrap_or(limits.command_timeout_ms);
    if timeout_ms == 0 || timeout_ms > limits.command_timeout_ms {
        return Err(BridgeError::invalid_argument(
            "command timeout exceeds the configured limit",
        ));
    }

    let host_name = request.host;
    let result = bridge
        .runner
        .execute(
            crate::ssh::RunRequest {
                host: host_name.clone(),
                command: request.command,
                cwd: cwd.as_str().to_owned(),
                shell: map_shell(request.shell),
                stdin,
                timeout: Duration::from_millis(timeout_ms),
            },
            cancel,
        )
        .await?;
    Ok(convert_result(host_name, result))
}

pub(super) fn decode_stdin(
    stdin: Option<RunStdin>,
    maximum: usize,
) -> BridgeResult<Option<Vec<u8>>> {
    let Some(stdin) = stdin else {
        return Ok(None);
    };
    let bytes = match stdin.encoding {
        WriteEncoding::Utf8 => stdin.value.into_bytes(),
        WriteEncoding::Base64 => {
            preflight_base64_length(&stdin.value, maximum)?;
            STANDARD.decode(stdin.value.as_bytes()).map_err(|_| {
                BridgeError::invalid_argument("stdin is not canonical standard Base64")
            })?
        }
    };
    if bytes.len() > maximum {
        return Err(BridgeError::new(
            ErrorCode::RequestTooLarge,
            "command input exceeds the configured limit",
            false,
        ));
    }
    Ok(Some(bytes))
}

fn preflight_base64_length(value: &str, maximum: usize) -> BridgeResult<()> {
    if value.is_empty() {
        return Ok(());
    }
    if !value.len().is_multiple_of(4) {
        return Err(BridgeError::invalid_argument(
            "stdin is not canonical standard Base64",
        ));
    }
    let padding = value.bytes().rev().take_while(|byte| *byte == b'=').count();
    if padding > 2 || value.as_bytes()[..value.len() - padding].contains(&b'=') {
        return Err(BridgeError::invalid_argument(
            "stdin is not canonical standard Base64",
        ));
    }
    let decoded_length = (value.len() / 4)
        .checked_mul(3)
        .and_then(|length| length.checked_sub(padding))
        .ok_or_else(command_input_too_large)?;
    if decoded_length > maximum {
        return Err(command_input_too_large());
    }
    Ok(())
}

fn command_input_too_large() -> BridgeError {
    BridgeError::new(
        ErrorCode::RequestTooLarge,
        "command input exceeds the configured limit",
        false,
    )
}

fn map_shell(shell: RunShell) -> ShellRequest {
    match shell {
        RunShell::Bash => ShellRequest::Bash,
        RunShell::Sh => ShellRequest::Sh,
        RunShell::Login => ShellRequest::Login,
    }
}

fn convert_result(host: String, result: crate::ssh::RunResult) -> RemoteRunResult {
    let crate::ssh::RunResult {
        status,
        elapsed_ms,
        shell,
        physical_root,
        output,
        remote_process_may_continue,
        helper_mode,
        timing: _,
    } = result;
    let CapturedOutput {
        stdout,
        stderr,
        reference,
        aggregate_bytes,
        ..
    } = output;
    let warnings = if matches!(shell.shell, ShellKind::PosixSh) {
        vec![POSIX_SH_WARNING.to_owned()]
    } else {
        Vec::new()
    };
    RemoteRunResult {
        context: protocol::context(host, physical_root, &shell, helper_mode),
        exit_status: status,
        elapsed_ms,
        stdout: encode_preview(stdout),
        stderr: encode_preview(stderr),
        aggregate_bytes,
        output_ref: reference.map(|reference| reference.as_str().to_owned()),
        remote_process_may_continue,
        warnings,
    }
}

fn encode_preview(preview: OutputPreview) -> EncodedOutputPreview {
    EncodedOutputPreview {
        head: protocol::encode_owned_bytes(preview.head),
        tail: protocol::encode_owned_bytes(preview.tail),
        raw_bytes: preview.bytes_seen,
        truncated: preview.truncated,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    use super::{RunStdin, WriteEncoding, decode_stdin};

    #[test]
    fn task78_base64_admission_release_rss() {
        run_base64_admission_release_rss();
    }

    fn run_base64_admission_release_rss() {
        const CHILD_ENV: &str = "CODEX_SSH_BRIDGE_BASE64_RSS_CHILD";
        const TEST_NAME: &str = "remote::run::tests::task78_base64_admission_release_rss";
        if cfg!(debug_assertions) {
            eprintln!("Base64 admission RSS assertion is release-only");
            return;
        }
        if std::env::var_os(CHILD_ENV).is_some() {
            base64_admission_rss_child();
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
        assert!(output.status.success(), "fresh Base64 RSS child failed");
        assert!(
            stdout.contains("Base64 admission release RSS:")
                || stderr.contains("Base64 admission release RSS:"),
            "fresh Base64 RSS child did not run the requested test"
        );
    }

    fn base64_admission_rss_child() {
        const WORKERS: usize = 5;
        const RSS_DELTA_CEILING_KIB: u64 = 32 * 1024;

        let inputs: Vec<_> = (0..WORKERS)
            .map(|_| RunStdin {
                encoding: WriteEncoding::Base64,
                value: maximum_zero_base64(),
            })
            .collect();
        let warmed = inputs
            .iter()
            .flat_map(|input| input.value.as_bytes().iter().step_by(4096))
            .fold(0u8, |sum, byte| sum.wrapping_add(*byte));
        std::hint::black_box(warmed);

        let start = Arc::new(Barrier::new(WORKERS + 1));
        let finish = Arc::new(Barrier::new(WORKERS + 1));
        let completed = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::with_capacity(WORKERS);
        for input in inputs {
            let start = Arc::clone(&start);
            let finish = Arc::clone(&finish);
            let completed = Arc::clone(&completed);
            workers.push(std::thread::spawn(move || {
                start.wait();
                let decoded = decode_stdin(Some(input), crate::MAX_WRITE_BYTES)
                    .unwrap()
                    .unwrap();
                assert_eq!(decoded.len(), crate::MAX_WRITE_BYTES);
                assert!(decoded.iter().all(|byte| *byte == 0));
                completed.fetch_add(1, Ordering::Release);
                finish.wait();
                decoded.len()
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
            assert_eq!(worker.join().unwrap(), crate::MAX_WRITE_BYTES);
        }
        let delta = peak.saturating_sub(baseline);
        eprintln!(
            "Base64 admission release RSS: baseline={baseline} KiB peak={peak} KiB delta={delta} KiB ceiling={RSS_DELTA_CEILING_KIB} KiB"
        );
        assert!(
            delta < RSS_DELTA_CEILING_KIB,
            "Base64 admission RSS baseline={baseline} peak={peak} delta={delta}"
        );
    }

    fn maximum_zero_base64() -> String {
        let encoded_length = crate::MAX_WRITE_BYTES.div_ceil(3) * 4;
        let mut value = "A".repeat(encoded_length);
        match crate::MAX_WRITE_BYTES % 3 {
            0 => {}
            1 => value.replace_range(encoded_length - 2.., "=="),
            2 => value.replace_range(encoded_length - 1.., "="),
            _ => unreachable!(),
        }
        value
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
}
