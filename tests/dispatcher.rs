use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command as TokioCommand;
use tokio::time::{Duration, timeout};

fn dispatcher_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/ssh/dispatcher.sh")
}

#[test]
fn dispatcher_script_exists_and_passes_posix_syntax_check() {
    let path = dispatcher_path();
    assert!(
        path.is_file(),
        "missing dispatcher script: {}",
        path.display()
    );
    let status = Command::new("/bin/sh")
        .args(["-n", path.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "dispatcher failed POSIX syntax check");
}

#[test]
fn dispatcher_script_declares_protocol_handshake_and_bounded_cleanup() {
    let script = std::fs::read_to_string(dispatcher_path()).unwrap();
    for required in [
        "codex-ssh-dispatcher-1",
        "CXSB1",
        "HELLO_ACK",
        "mkfifo",
        "setsid",
        "trap cleanup",
        "MAX_FRAME_BYTES",
    ] {
        assert!(
            script.contains(required),
            "dispatcher is missing {required}"
        );
    }
}

async fn read_frame(
    reader: &mut BufReader<impl tokio::io::AsyncRead + Unpin>,
) -> (String, u64, Vec<u8>) {
    let mut header = String::new();
    reader.read_line(&mut header).await.unwrap();
    let fields = header.split_ascii_whitespace().collect::<Vec<_>>();
    assert_eq!(fields.len(), 4, "bad dispatcher header: {header:?}");
    let length = fields[3].parse::<usize>().unwrap();
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload).await.unwrap();
    (fields[1].to_owned(), fields[2].parse().unwrap(), payload)
}

async fn write_frame(
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
    kind: &str,
    id: u64,
    payload: &[u8],
) {
    writer
        .write_all(format!("CXSB1 {kind} {id} {}\n", payload.len()).as_bytes())
        .await
        .unwrap();
    writer.write_all(payload).await.unwrap();
}

#[tokio::test]
async fn dispatcher_executes_shell_command_and_preserves_streams_and_exit_status() {
    let temp = tempfile::TempDir::new().unwrap();
    let watchdog_log = temp.path().join("watchdog-pids");
    let bin = temp.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let sleep = bin.join("sleep");
    std::fs::write(
        &sleep,
        b"#!/bin/sh\nprintf '%s\\n' \"$$\" >>\"$WATCHDOG_LOG\"\nexec /bin/sleep \"$@\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&sleep, std::fs::Permissions::from_mode(0o755)).unwrap();
    let script = std::fs::read_to_string(dispatcher_path()).unwrap();
    let mut child = TokioCommand::new("/bin/sh")
        .args(["-c", &script, "--", "codex-ssh-dispatcher-1"])
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("WATCHDOG_LOG", &watchdog_log)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut output = BufReader::new(stdout);
    let (kind, id, payload) = timeout(Duration::from_secs(3), read_frame(&mut output))
        .await
        .expect("dispatcher did not send handshake");
    assert_eq!((kind.as_str(), id), ("HELLO_ACK", 0));
    assert!(
        String::from_utf8(payload)
            .unwrap()
            .contains("codex-ssh-dispatcher/1")
    );

    let cwd = temp.path().as_os_str().as_encoded_bytes();
    let command = b"printf out; printf err >&2; exit 7";
    let metadata = format!(
        "shell=sh\ncwd_length={}\ncommand_length={}\nstdin_length=0\ntimeout_ms=5000\nstdout_limit=1024\nstderr_limit=1024\n",
        cwd.len(),
        command.len()
    );
    write_frame(&mut stdin, "OPEN", 1, metadata.as_bytes()).await;
    write_frame(&mut stdin, "DATA", 1, cwd).await;
    write_frame(&mut stdin, "DATA", 1, command).await;
    stdin.flush().await.unwrap();

    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let mut exit = None;
    for _ in 0..8 {
        let (kind, id, payload) = timeout(Duration::from_secs(3), read_frame(&mut output))
            .await
            .expect("dispatcher did not send response");
        assert_eq!(id, 1);
        match kind.as_str() {
            "READY" => assert_eq!(payload, b"started"),
            "STDOUT" => stdout_bytes.extend_from_slice(&payload),
            "STDERR" => stderr_bytes.extend_from_slice(&payload),
            "EXIT" => {
                exit = Some(String::from_utf8(payload).unwrap());
                break;
            }
            other => panic!("unexpected dispatcher frame {other}"),
        }
    }
    assert_eq!(stdout_bytes, b"out");
    assert_eq!(stderr_bytes, b"err");
    assert_eq!(exit.as_deref(), Some("7\n0\n0\n0\n0\n"));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let watchdog_pids = std::fs::read_to_string(&watchdog_log).unwrap();
    for pid in watchdog_pids.lines() {
        let status = Command::new("/bin/sh")
            .args(["-c", "kill -0 \"$1\" 2>/dev/null", "--", pid])
            .status()
            .unwrap();
        assert!(
            !status.success(),
            "watchdog sleep {pid} survived its request"
        );
    }
    write_frame(&mut stdin, "CLOSE", 0, &[]).await;
    drop(stdin);
    assert!(child.wait().await.unwrap().success());
}
