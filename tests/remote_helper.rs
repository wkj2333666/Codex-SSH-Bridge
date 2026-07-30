use std::io::{BufReader, Cursor, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use codex_ssh_bridge::remote_helper_protocol::{Frame, FrameKind, read_frame, write_frame};

#[test]
fn helper_wire_round_trips_binary_and_empty_payloads() {
    let frames = [
        Frame {
            kind: FrameKind::Stdout,
            request_id: 7,
            payload: vec![0, b'\n', 0xff],
        },
        Frame {
            kind: FrameKind::Ready,
            request_id: 7,
            payload: Vec::new(),
        },
    ];
    let mut bytes = Vec::new();
    for frame in &frames {
        write_frame(&mut bytes, frame, 64).unwrap();
    }
    let mut input = bytes.as_slice();
    assert_eq!(read_frame(&mut input, 64).unwrap(), Some(frames[0].clone()));
    assert_eq!(read_frame(&mut input, 64).unwrap(), Some(frames[1].clone()));
    assert_eq!(read_frame(&mut input, 64).unwrap(), None);
}

#[test]
fn helper_wire_rejects_oversized_and_truncated_payloads() {
    let oversized = Frame {
        kind: FrameKind::Data,
        request_id: 1,
        payload: vec![1, 2, 3],
    };
    let mut output = Vec::new();
    assert!(write_frame(&mut output, &oversized, 2).is_err());

    let mut truncated = Cursor::new(b"CXSB1 DATA 1 4\nxy".to_vec());
    assert!(read_frame(&mut truncated, 64).is_err());
}

fn helper_path() -> PathBuf {
    std::env::var("CARGO_BIN_EXE_codex-ssh-bridge-helper")
        .or_else(|_| std::env::var("CARGO_BIN_EXE_codex_ssh_bridge_helper"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/debug/codex-ssh-bridge-helper")
        })
}

fn helper_child() -> std::process::Child {
    Command::new(helper_path())
        .args(["--max-frame", "65536"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn helper binary")
}

fn read_next(reader: &mut BufReader<impl std::io::Read>) -> Frame {
    read_frame(reader, 65536)
        .expect("helper frame read failed")
        .expect("helper closed unexpectedly")
}

fn send_frame(writer: &mut impl Write, frame: Frame) {
    write_frame(writer, &frame, 65536).expect("helper frame write failed");
    writer.flush().expect("helper stdin flush failed");
}

fn send_request(writer: &mut impl Write, request_id: u64, cwd: &[u8], command: &[u8]) {
    send_request_with_limits(writer, request_id, cwd, command, 1024, 1024);
}

fn send_request_with_limits(
    writer: &mut impl Write,
    request_id: u64,
    cwd: &[u8],
    command: &[u8],
    stdout_limit: u64,
    stderr_limit: u64,
) {
    send_request_with_options(
        writer,
        request_id,
        cwd,
        command,
        stdout_limit,
        stderr_limit,
        2_000,
    );
}

fn send_request_with_options(
    writer: &mut impl Write,
    request_id: u64,
    cwd: &[u8],
    command: &[u8],
    stdout_limit: u64,
    stderr_limit: u64,
    timeout_ms: u64,
) {
    let metadata = format!(
        "shell=sh\ncwd_length={}\ncommand_length={}\nstdin_length=0\ntimeout_ms={timeout_ms}\nstdout_limit={stdout_limit}\nstderr_limit={stderr_limit}\n",
        cwd.len(),
        command.len()
    );
    send_frame(
        writer,
        Frame {
            kind: FrameKind::Open,
            request_id,
            payload: metadata.into_bytes(),
        },
    );
    send_frame(
        writer,
        Frame {
            kind: FrameKind::Data,
            request_id,
            payload: cwd.to_vec(),
        },
    );
    send_frame(
        writer,
        Frame {
            kind: FrameKind::Data,
            request_id,
            payload: command.to_vec(),
        },
    );
}

fn send_search_request(
    writer: &mut impl Write,
    request_id: u64,
    root: &[u8],
    query: &[u8],
    globs: &[u8],
) {
    send_search_request_with_timeout(writer, request_id, root, query, globs, 2_000);
}

fn send_search_request_with_timeout(
    writer: &mut impl Write,
    request_id: u64,
    root: &[u8],
    query: &[u8],
    globs: &[u8],
    timeout_ms: u64,
) {
    let metadata = format!(
        concat!(
            "operation=search\n",
            "root_length={}\n",
            "query_length={}\n",
            "globs_length={}\n",
            "max_results=10\n",
            "binary=0\n",
            "timeout_ms={}\n",
            "stdout_limit=65536\n",
            "stderr_limit=1024\n",
        ),
        root.len(),
        query.len(),
        globs.len(),
        timeout_ms,
    );
    send_frame(
        writer,
        Frame {
            kind: FrameKind::Open,
            request_id,
            payload: metadata.into_bytes(),
        },
    );
    for payload in [root, query, globs] {
        send_frame(
            writer,
            Frame {
                kind: FrameKind::Data,
                request_id,
                payload: payload.to_vec(),
            },
        );
    }
}

fn decode_search_match(payload: &[u8]) -> (&[u8], u64, u64, &[u8]) {
    const HEADER_BYTES: usize = 5 + 4 + 8 + 8 + 4;
    assert!(payload.len() >= HEADER_BYTES, "short search match record");
    assert_eq!(&payload[..5], b"CXSM1");
    let path_bytes = u32::from_le_bytes(payload[5..9].try_into().unwrap()) as usize;
    let line = u64::from_le_bytes(payload[9..17].try_into().unwrap());
    let column = u64::from_le_bytes(payload[17..25].try_into().unwrap());
    let content_bytes = u32::from_le_bytes(payload[25..29].try_into().unwrap()) as usize;
    assert_eq!(
        payload.len(),
        HEADER_BYTES + path_bytes + content_bytes,
        "search record lengths do not match its frame"
    );
    let path_end = HEADER_BYTES + path_bytes;
    (
        &payload[HEADER_BYTES..path_end],
        line,
        column,
        &payload[path_end..],
    )
}

#[test]
fn helper_searches_natively_and_returns_structured_matches() {
    let temp = tempfile::tempdir().unwrap();
    let nested = temp.path().join("src");
    std::fs::create_dir(&nested).unwrap();
    let target = nested.join("tail.py");
    std::fs::write(&target, b"needle here\n").unwrap();
    std::fs::write(nested.join("ignored.txt"), b"needle ignored\n").unwrap();
    let root = temp.path().as_os_str().as_encoded_bytes();
    let mut child = helper_child();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let _ = read_next(&mut output);

    send_search_request(&mut input, 1, root, b"needle", b"*.py\0");
    let mut ready = false;
    let mut matches = Vec::new();
    let exit = loop {
        let frame = read_next(&mut output);
        assert_eq!(frame.request_id, 1);
        match frame.kind {
            FrameKind::Ready => ready = true,
            FrameKind::Stdout => matches.push(frame.payload),
            FrameKind::Exit => break frame.payload,
            other => panic!("unexpected native search frame {other:?}"),
        }
    };

    assert!(ready, "helper did not admit the native search");
    assert_eq!(matches.len(), 1);
    let (path, line, column, content) = decode_search_match(&matches[0]);
    assert_eq!(path, target.as_os_str().as_encoded_bytes());
    assert_eq!((line, column), (1, 1));
    assert_eq!(content, b"needle here");
    assert_eq!(exit, b"0\n0\n0\n0\n0\n");
    send_frame(
        &mut input,
        Frame {
            kind: FrameKind::Close,
            request_id: 0,
            payload: Vec::new(),
        },
    );
    drop(input);
    assert!(child.wait().unwrap().success());
}

#[test]
fn native_search_omits_binary_files_after_a_literal_match() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("binary.py"), b"needle\0binary\n").unwrap();
    let root = temp.path().as_os_str().as_encoded_bytes();
    let mut child = helper_child();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let _ = read_next(&mut output);

    send_search_request(&mut input, 1, root, b"needle", b"*.py\0");
    let mut matches = 0;
    let exit = loop {
        let frame = read_next(&mut output);
        assert_eq!(frame.request_id, 1);
        match frame.kind {
            FrameKind::Stdout => matches += 1,
            FrameKind::Exit => break frame.payload,
            _ => {}
        }
    };

    assert_eq!(matches, 0);
    assert_eq!(exit, b"0\n0\n0\n0\n0\n");
    send_frame(
        &mut input,
        Frame {
            kind: FrameKind::Close,
            request_id: 0,
            payload: Vec::new(),
        },
    );
    drop(input);
    assert!(child.wait().unwrap().success());
}

#[test]
fn native_search_scans_large_unmatched_files_within_its_deadline() {
    let temp = tempfile::tempdir().unwrap();
    let large = std::fs::File::create(temp.path().join("large.py")).unwrap();
    large.set_len(512 * 1024 * 1024).unwrap();
    drop(large);
    let root = temp.path().as_os_str().as_encoded_bytes();
    let mut child = helper_child();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let _ = read_next(&mut output);

    let started = Instant::now();
    send_search_request_with_timeout(&mut input, 1, root, b"not-present", b"*.py\0", 3_000);
    let exit = loop {
        let frame = read_next(&mut output);
        assert_eq!(frame.request_id, 1);
        if frame.kind == FrameKind::Exit {
            break frame.payload;
        }
    };

    assert_eq!(
        exit,
        b"0\n0\n0\n0\n0\n",
        "native search exceeded its own 3s scan deadline after {:?}",
        started.elapsed()
    );
    send_frame(
        &mut input,
        Frame {
            kind: FrameKind::Close,
            request_id: 0,
            payload: Vec::new(),
        },
    );
    drop(input);
    assert!(child.wait().unwrap().success());
}

#[test]
fn cancelling_native_search_keeps_the_helper_reusable() {
    let temp = tempfile::tempdir().unwrap();
    let large = std::fs::File::create(temp.path().join("large.bin")).unwrap();
    large.set_len(64 * 1024 * 1024).unwrap();
    drop(large);
    let root = temp.path().as_os_str().as_encoded_bytes();
    let mut child = helper_child();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let _ = read_next(&mut output);

    send_search_request(&mut input, 1, root, b"not-present", b"");
    send_frame(
        &mut input,
        Frame {
            kind: FrameKind::Cancel,
            request_id: 1,
            payload: Vec::new(),
        },
    );
    let cancelled = loop {
        let frame = read_next(&mut output);
        assert_eq!(frame.request_id, 1);
        if frame.kind == FrameKind::Exit {
            break frame.payload;
        }
    };
    assert_eq!(cancelled, b"130\n0\n0\n0\n0\n");

    let cwd = temp.path().as_os_str().as_encoded_bytes();
    send_request(&mut input, 2, cwd, b"printf reusable");
    let mut stdout = Vec::new();
    let follow_up = loop {
        let frame = read_next(&mut output);
        assert_eq!(frame.request_id, 2);
        match frame.kind {
            FrameKind::Stdout => stdout.extend_from_slice(&frame.payload),
            FrameKind::Exit => break frame.payload,
            _ => {}
        }
    };
    assert_eq!(stdout, b"reusable");
    assert_eq!(follow_up, b"0\n0\n0\n0\n0\n");

    send_frame(
        &mut input,
        Frame {
            kind: FrameKind::Close,
            request_id: 0,
            payload: Vec::new(),
        },
    );
    drop(input);
    assert!(child.wait().unwrap().success());
}

#[test]
fn helper_marks_its_own_watchdog_timeout_explicitly() {
    let temp = tempfile::tempdir().unwrap();
    let cwd = temp.path().as_os_str().as_encoded_bytes();
    let mut child = helper_child();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let _ = read_next(&mut output);
    send_request_with_options(&mut input, 1, cwd, b"sleep 10", 1024, 1024, 50);
    let deadline = Instant::now() + Duration::from_secs(2);
    let exit = loop {
        assert!(Instant::now() < deadline, "helper watchdog did not fire");
        let frame = read_next(&mut output);
        if frame.kind == FrameKind::Exit {
            break frame.payload;
        }
    };
    let fields = std::str::from_utf8(&exit)
        .unwrap()
        .lines()
        .collect::<Vec<_>>();
    assert_eq!(fields.len(), 5);
    assert_eq!(fields[4], "1");
    send_frame(
        &mut input,
        Frame {
            kind: FrameKind::Close,
            request_id: 0,
            payload: Vec::new(),
        },
    );
    drop(input);
    assert!(child.wait().unwrap().success());
}

#[test]
fn helper_preserves_streams_and_exit_status() {
    let temp = tempfile::tempdir().unwrap();
    let cwd = temp.path().as_os_str().as_encoded_bytes();
    let mut child = helper_child();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let hello = read_next(&mut output);
    assert_eq!(hello.kind, FrameKind::HelloAck);
    assert_eq!(hello.request_id, 0);
    assert!(
        String::from_utf8(hello.payload)
            .unwrap()
            .contains("protocol=codex-ssh-helper/1;version=1;")
    );

    send_request(&mut input, 1, cwd, b"printf out; printf err >&2; exit 7");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut ready = false;
    let mut exit = None;
    for _ in 0..8 {
        let frame = read_next(&mut output);
        assert_eq!(frame.request_id, 1);
        match frame.kind {
            FrameKind::Ready => {
                assert!(!ready, "helper sent READY more than once");
                ready = true;
            }
            FrameKind::Stdout => stdout.extend_from_slice(&frame.payload),
            FrameKind::Stderr => stderr.extend_from_slice(&frame.payload),
            FrameKind::Exit => {
                exit = Some(frame.payload);
                break;
            }
            other => panic!("unexpected helper frame {other:?}"),
        }
    }
    assert!(ready, "helper did not acknowledge request admission");
    assert_eq!(stdout, b"out");
    assert_eq!(stderr, b"err");
    assert_eq!(exit.as_deref(), Some(b"7\n0\n0\n0\n0\n".as_slice()));
    send_frame(
        &mut input,
        Frame {
            kind: FrameKind::Close,
            request_id: 0,
            payload: Vec::new(),
        },
    );
    drop(input);
    assert!(child.wait().unwrap().success());
}

#[test]
fn helper_completes_parent_before_pipe_inheriting_child_exits() {
    let temp = tempfile::tempdir().unwrap();
    let cwd = temp.path().as_os_str().as_encoded_bytes();
    let mut child = helper_child();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let _ = read_next(&mut output);
    send_request(&mut input, 1, cwd, b"trap '' TERM; sleep 10 & exit 0");
    let deadline = Instant::now() + Duration::from_secs(2);
    let exit = loop {
        assert!(
            Instant::now() < deadline,
            "helper withheld EXIT for an orphan"
        );
        let frame = read_next(&mut output);
        if frame.kind == FrameKind::Exit {
            break frame.payload;
        }
    };
    assert_eq!(exit, b"0\n0\n0\n1\n0\n");
    // The completed request must release the helper worker even though its
    // descendant still owns the old pipes.
    send_request(&mut input, 2, cwd, b"printf follow-up");
    let follow_up = loop {
        let frame = read_next(&mut output);
        assert_eq!(frame.request_id, 2);
        if frame.kind == FrameKind::Exit {
            break frame.payload;
        }
    };
    assert_eq!(follow_up, b"0\n0\n0\n0\n0\n");
    send_frame(
        &mut input,
        Frame {
            kind: FrameKind::Cancel,
            request_id: 1,
            payload: Vec::new(),
        },
    );
    send_frame(
        &mut input,
        Frame {
            kind: FrameKind::Close,
            request_id: 0,
            payload: Vec::new(),
        },
    );
    drop(input);
    assert!(child.wait().unwrap().success());
}

#[test]
fn helper_runs_requests_concurrently() {
    let temp = tempfile::tempdir().unwrap();
    let cwd = temp.path().as_os_str().as_encoded_bytes();
    let mut child = helper_child();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let _ = read_next(&mut output);
    send_request(&mut input, 1, cwd, b"sleep 0.15; printf one");
    send_request(&mut input, 2, cwd, b"sleep 0.15; printf two");
    let started = Instant::now();
    let mut completed = [false; 2];
    while !completed[0] || !completed[1] {
        let frame = read_next(&mut output);
        if frame.kind == FrameKind::Exit {
            completed[(frame.request_id - 1) as usize] = true;
        }
    }
    assert!(started.elapsed() < Duration::from_millis(500));
    send_frame(
        &mut input,
        Frame {
            kind: FrameKind::Close,
            request_id: 0,
            payload: Vec::new(),
        },
    );
    drop(input);
    assert!(child.wait().unwrap().success());
}

#[test]
fn helper_drains_beyond_output_limit_and_reports_truncation() {
    let temp = tempfile::tempdir().unwrap();
    let cwd = temp.path().as_os_str().as_encoded_bytes();
    let mut child = helper_child();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let _ = read_next(&mut output);
    send_request_with_limits(&mut input, 1, cwd, b"printf 12345", 3, 1024);
    let mut stdout = Vec::new();
    let exit = loop {
        let frame = read_next(&mut output);
        match frame.kind {
            FrameKind::Stdout => stdout.extend_from_slice(&frame.payload),
            FrameKind::Exit => break frame.payload,
            _ => {}
        }
    };
    assert_eq!(stdout, b"123");
    assert_eq!(exit, b"0\n1\n0\n0\n0\n");
    send_frame(
        &mut input,
        Frame {
            kind: FrameKind::Close,
            request_id: 0,
            payload: Vec::new(),
        },
    );
    drop(input);
    assert!(child.wait().unwrap().success());
}

#[test]
fn helper_cancel_terminates_the_request_process_group() {
    let temp = tempfile::tempdir().unwrap();
    let cwd = temp.path().as_os_str().as_encoded_bytes();
    let mut child = helper_child();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let _ = read_next(&mut output);
    send_request(&mut input, 1, cwd, b"trap '' TERM; sleep 5");
    send_frame(
        &mut input,
        Frame {
            kind: FrameKind::Cancel,
            request_id: 1,
            payload: Vec::new(),
        },
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut saw_exit = false;
    while Instant::now() < deadline {
        let frame = read_next(&mut output);
        if frame.kind == FrameKind::Exit {
            saw_exit = true;
            break;
        }
    }
    assert!(saw_exit, "cancelled helper request did not finish");
    send_frame(
        &mut input,
        Frame {
            kind: FrameKind::Close,
            request_id: 0,
            payload: Vec::new(),
        },
    );
    drop(input);
    assert!(child.wait().unwrap().success());
}
