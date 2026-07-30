//! The small, synchronous executor uploaded to supported remote hosts.
//!
//! This module deliberately has no Tokio dependency in its implementation.
//! The main bridge uses Tokio locally; the helper only needs framed stdio,
//! process groups, and a few worker threads on the remote machine.

use std::collections::{BTreeMap, HashMap};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use memchr::{memchr, memchr_iter, memmem};

use crate::remote_helper_protocol::{Frame, FrameKind, read_frame, write_frame};

const HELPER_PROTOCOL: &str = "codex-ssh-helper/1";
const DEFAULT_HELPER_VERSION: &str = "1";
const STREAM_BUFFER_BYTES: usize = 64 * 1024;
const TERM_GRACE: Duration = Duration::from_millis(50);
const DESCENDANT_DRAIN_GRACE: Duration = Duration::from_millis(120);
const TIMEOUT_PIPE_CLOSE_GRACE: Duration = Duration::from_millis(25);

#[derive(Debug, Clone, Copy)]
pub struct HelperConfig {
    pub max_frame_bytes: usize,
    pub helper_version: &'static str,
}

impl HelperConfig {
    pub const fn new(max_frame_bytes: usize) -> Self {
        Self {
            max_frame_bytes,
            helper_version: DEFAULT_HELPER_VERSION,
        }
    }
}

struct Shared<W> {
    writer: Mutex<W>,
    max_frame_bytes: usize,
    requests: Mutex<HashMap<u64, Arc<RequestControl>>>,
    closed: AtomicBool,
}

struct RequestControl {
    process_group: AtomicI32,
    cancelled: AtomicBool,
}

struct StreamDrainState {
    pipe_closed: AtomicBool,
    truncated: AtomicBool,
    stop_sending: Arc<AtomicBool>,
}

impl StreamDrainState {
    fn new(stop_sending: Arc<AtomicBool>) -> Self {
        Self {
            pipe_closed: AtomicBool::new(false),
            truncated: AtomicBool::new(false),
            stop_sending,
        }
    }
}

impl RequestControl {
    fn new() -> Self {
        Self {
            process_group: AtomicI32::new(0),
            cancelled: AtomicBool::new(false),
        }
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        terminate_process_group(self.process_group.load(Ordering::Acquire));
    }
}

#[derive(Debug)]
enum RequestSpec {
    Command(CommandSpec),
    Search(SearchSpec),
}

impl RequestSpec {
    fn request_id(&self) -> u64 {
        match self {
            Self::Command(spec) => spec.request_id,
            Self::Search(spec) => spec.request_id,
        }
    }
}

#[derive(Debug)]
struct CommandSpec {
    request_id: u64,
    shell: String,
    cwd: PathBuf,
    command: String,
    stdin: Vec<u8>,
    login_shell: Option<String>,
    timeout: Duration,
    stdout_limit: u64,
    stderr_limit: u64,
}

#[derive(Debug)]
struct SearchSpec {
    request_id: u64,
    root: PathBuf,
    query: Vec<u8>,
    globs: Vec<String>,
    max_results: usize,
    binary: bool,
    timeout: Duration,
    stdout_limit: u64,
}

pub fn run<R, W>(mut reader: R, writer: W, config: HelperConfig) -> io::Result<()>
where
    R: Read,
    W: Write + Send + 'static,
{
    if config.max_frame_bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "helper frame limit must be positive",
        ));
    }
    let shared = Arc::new(Shared {
        writer: Mutex::new(writer),
        max_frame_bytes: config.max_frame_bytes,
        requests: Mutex::new(HashMap::new()),
        closed: AtomicBool::new(false),
    });
    send_hello(&shared, config.helper_version)?;

    let mut workers = Vec::new();
    loop {
        let Some(frame) = read_frame(&mut reader, config.max_frame_bytes)? else {
            break;
        };
        match frame.kind {
            FrameKind::Hello => send_hello_for_request(&shared, frame.request_id)?,
            FrameKind::Open => {
                if frame.request_id == 0 {
                    send_error(&shared, 0, "invalid-request-id")?;
                    continue;
                }
                let request_id = frame.request_id;
                match read_request(&mut reader, frame, config.max_frame_bytes) {
                    Ok(spec) => {
                        let control = Arc::new(RequestControl::new());
                        let duplicate = {
                            let mut requests = shared.requests.lock().map_err(lock_error)?;
                            match requests.entry(spec.request_id()) {
                                std::collections::hash_map::Entry::Vacant(entry) => {
                                    entry.insert(Arc::clone(&control));
                                    false
                                }
                                std::collections::hash_map::Entry::Occupied(_) => true,
                            }
                        };
                        if duplicate {
                            send_error(&shared, spec.request_id(), "duplicate-request-id")?;
                            continue;
                        }
                        send_frame(
                            &shared,
                            Frame {
                                kind: FrameKind::Ready,
                                request_id: spec.request_id(),
                                payload: Vec::new(),
                            },
                        )?;
                        let worker_shared = Arc::clone(&shared);
                        workers.push(thread::spawn(move || {
                            run_request(worker_shared, spec, control);
                        }));
                    }
                    Err(message) => send_error(&shared, request_id, &message)?,
                }
            }
            FrameKind::Cancel => {
                if let Some(control) = shared
                    .requests
                    .lock()
                    .map_err(lock_error)?
                    .get(&frame.request_id)
                    .cloned()
                {
                    control.cancel();
                }
            }
            FrameKind::Close => break,
            _ => send_error(&shared, frame.request_id, "unexpected-frame")?,
        }
    }

    shared.closed.store(true, Ordering::Release);
    for control in shared
        .requests
        .lock()
        .map_err(lock_error)?
        .values()
        .cloned()
        .collect::<Vec<_>>()
    {
        control.cancel();
    }
    for worker in workers {
        let _ = worker.join();
    }
    Ok(())
}

fn send_hello<W: Write>(shared: &Arc<Shared<W>>, version: &str) -> io::Result<()> {
    let payload = format!(
        "protocol={HELPER_PROTOCOL};version={version};arch={};",
        machine_arch()
    );
    send_frame(
        shared,
        Frame {
            kind: FrameKind::HelloAck,
            request_id: 0,
            payload: payload.into_bytes(),
        },
    )
}

fn send_hello_for_request<W: Write>(shared: &Arc<Shared<W>>, request_id: u64) -> io::Result<()> {
    let payload = format!(
        "protocol={HELPER_PROTOCOL};version={};arch={};",
        DEFAULT_HELPER_VERSION,
        machine_arch()
    );
    send_frame(
        shared,
        Frame {
            kind: FrameKind::HelloAck,
            request_id,
            payload: payload.into_bytes(),
        },
    )
}

fn send_error<W: Write>(shared: &Arc<Shared<W>>, request_id: u64, message: &str) -> io::Result<()> {
    send_frame(
        shared,
        Frame {
            kind: FrameKind::Error,
            request_id,
            payload: message.as_bytes().to_vec(),
        },
    )
}

fn send_frame<W: Write>(shared: &Arc<Shared<W>>, frame: Frame) -> io::Result<()> {
    let mut writer = shared.writer.lock().map_err(lock_error)?;
    write_frame(&mut *writer, &frame, shared.max_frame_bytes)?;
    writer.flush()
}

fn send_stream_frame<W: Write>(
    shared: &Arc<Shared<W>>,
    frame: Frame,
    stop_sending: &AtomicBool,
) -> io::Result<()> {
    let mut writer = shared.writer.lock().map_err(lock_error)?;
    if stop_sending.load(Ordering::Acquire) {
        return Ok(());
    }
    write_frame(&mut *writer, &frame, shared.max_frame_bytes)?;
    writer.flush()
}

fn read_request<R: Read>(
    reader: &mut R,
    open: Frame,
    max_frame_bytes: usize,
) -> Result<RequestSpec, String> {
    let fields = parse_metadata(&open.payload)?;
    if fields.get("operation").map(String::as_str) == Some("search") {
        ensure_search_fields(&fields)?;
        return read_search_request(reader, open, fields, max_frame_bytes);
    }
    if fields.contains_key("operation") {
        return Err("invalid-open-metadata".to_owned());
    }
    ensure_command_fields(&fields)?;
    let shell = required_field(&fields, "shell")?.to_owned();
    let cwd_length = parse_length(&fields, "cwd_length")?;
    let command_length = parse_length(&fields, "command_length")?;
    let stdin_length = parse_length(&fields, "stdin_length")?;
    let timeout_ms = parse_u64(&fields, "timeout_ms")?;
    let stdout_limit = parse_u64(&fields, "stdout_limit")?;
    let stderr_limit = parse_u64(&fields, "stderr_limit")?;
    let login_shell = match fields.get("login_shell").map(String::as_str) {
        Some("") | None => None,
        Some(value)
            if value.starts_with('/') && !value.bytes().any(|byte| byte.is_ascii_control()) =>
        {
            Some(value.to_owned())
        }
        Some(_) => return Err("invalid-login-shell".to_owned()),
    };
    match shell.as_str() {
        "bash" | "sh" if login_shell.is_none() => {}
        "login" if login_shell.is_some() => {}
        "bash" | "sh" | "login" => return Err("invalid-open-metadata".to_owned()),
        _ => return Err("unsupported-shell".to_owned()),
    }
    let cwd = String::from_utf8(read_data(reader, &open, cwd_length, max_frame_bytes)?)
        .map_err(|_| "cwd-is-not-utf8".to_owned())?;
    let command = String::from_utf8(read_data(reader, &open, command_length, max_frame_bytes)?)
        .map_err(|_| "command-is-not-utf8".to_owned())?;
    let stdin = if stdin_length == 0 {
        Vec::new()
    } else {
        read_data(reader, &open, stdin_length, max_frame_bytes)?
    };
    Ok(RequestSpec::Command(CommandSpec {
        request_id: open.request_id,
        shell,
        cwd: PathBuf::from(cwd),
        command,
        stdin,
        login_shell,
        timeout: Duration::from_millis(timeout_ms),
        stdout_limit,
        stderr_limit,
    }))
}

fn ensure_command_fields(fields: &BTreeMap<String, String>) -> Result<(), String> {
    const REQUIRED: &[&str] = &[
        "shell",
        "cwd_length",
        "command_length",
        "stdin_length",
        "timeout_ms",
        "stdout_limit",
        "stderr_limit",
    ];
    if REQUIRED.iter().any(|key| !fields.contains_key(*key))
        || fields
            .keys()
            .any(|key| !REQUIRED.contains(&key.as_str()) && key.as_str() != "login_shell")
    {
        return Err("invalid-open-metadata".to_owned());
    }
    Ok(())
}

fn ensure_search_fields(fields: &BTreeMap<String, String>) -> Result<(), String> {
    const REQUIRED: &[&str] = &[
        "operation",
        "root_length",
        "query_length",
        "globs_length",
        "max_results",
        "binary",
        "timeout_ms",
        "stdout_limit",
        "stderr_limit",
    ];
    if fields.len() != REQUIRED.len() || REQUIRED.iter().any(|key| !fields.contains_key(*key)) {
        return Err("invalid-open-metadata".to_owned());
    }
    Ok(())
}

fn read_search_request<R: Read>(
    reader: &mut R,
    open: Frame,
    fields: BTreeMap<String, String>,
    max_frame_bytes: usize,
) -> Result<RequestSpec, String> {
    let root_length = parse_length(&fields, "root_length")?;
    let query_length = parse_length(&fields, "query_length")?;
    let globs_length = parse_length(&fields, "globs_length")?;
    let max_results = parse_length(&fields, "max_results")?;
    let binary = match required_field(&fields, "binary")? {
        "0" => false,
        "1" => true,
        _ => return Err("invalid-open-metadata".to_owned()),
    };
    let timeout = Duration::from_millis(parse_u64(&fields, "timeout_ms")?);
    let stdout_limit = parse_u64(&fields, "stdout_limit")?;
    let _stderr_limit = parse_u64(&fields, "stderr_limit")?;
    let root = String::from_utf8(read_data(reader, &open, root_length, max_frame_bytes)?)
        .map_err(|_| "root-is-not-utf8".to_owned())?;
    if root.as_bytes().contains(&0) {
        return Err("invalid-search-root".to_owned());
    }
    let query = read_data(reader, &open, query_length, max_frame_bytes)?;
    if query.is_empty() {
        return Err("invalid-search-query".to_owned());
    }
    let glob_bytes = read_data(reader, &open, globs_length, max_frame_bytes)?;
    let mut globs = Vec::new();
    for glob in glob_bytes.split(|byte| *byte == 0) {
        if glob.is_empty() {
            continue;
        }
        let glob = std::str::from_utf8(glob)
            .map_err(|_| "search-glob-is-not-utf8".to_owned())?
            .to_owned();
        validate_glob(&glob)?;
        globs.push(glob);
    }
    Ok(RequestSpec::Search(SearchSpec {
        request_id: open.request_id,
        root: PathBuf::from(root),
        query,
        globs,
        max_results,
        binary,
        timeout,
        stdout_limit,
    }))
}

fn read_data<R: Read>(
    reader: &mut R,
    open: &Frame,
    expected_length: usize,
    max_frame_bytes: usize,
) -> Result<Vec<u8>, String> {
    let frame = read_frame(reader, max_frame_bytes)
        .map_err(|_| "truncated-request-data".to_owned())?
        .ok_or_else(|| "truncated-request-data".to_owned())?;
    if frame.kind != FrameKind::Data
        || frame.request_id != open.request_id
        || frame.payload.len() != expected_length
    {
        return Err("invalid-request-data".to_owned());
    }
    Ok(frame.payload)
}

fn parse_metadata(payload: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let text = std::str::from_utf8(payload).map_err(|_| "metadata-is-not-utf8".to_owned())?;
    let mut fields = BTreeMap::new();
    for line in text.split('\n') {
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| "invalid-open-metadata".to_owned())?;
        if !matches!(
            key,
            "shell"
                | "operation"
                | "cwd_length"
                | "command_length"
                | "stdin_length"
                | "root_length"
                | "query_length"
                | "globs_length"
                | "max_results"
                | "binary"
                | "login_shell"
                | "timeout_ms"
                | "stdout_limit"
                | "stderr_limit"
        ) || fields.insert(key.to_owned(), value.to_owned()).is_some()
        {
            return Err("invalid-open-metadata".to_owned());
        }
    }
    Ok(fields)
}

fn required_field<'a>(fields: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, String> {
    fields
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| "invalid-open-metadata".to_owned())
}

fn parse_length(fields: &BTreeMap<String, String>, key: &str) -> Result<usize, String> {
    parse_u64(fields, key)?
        .try_into()
        .map_err(|_| "invalid-open-number".to_owned())
}

fn parse_u64(fields: &BTreeMap<String, String>, key: &str) -> Result<u64, String> {
    let value = required_field(fields, key)?;
    if value.is_empty() || value.bytes().any(|byte| !byte.is_ascii_digit()) {
        return Err("invalid-open-number".to_owned());
    }
    value
        .parse::<u64>()
        .map_err(|_| "invalid-open-number".to_owned())
}

fn run_request<W>(shared: Arc<Shared<W>>, spec: RequestSpec, control: Arc<RequestControl>)
where
    W: Write + Send + 'static,
{
    if let Err(message) = execute_request(&shared, &spec, &control) {
        let _ = send_error(&shared, spec.request_id(), &message);
    }
    if let Ok(mut requests) = shared.requests.lock() {
        requests.remove(&spec.request_id());
    }
}

fn execute_request<W>(
    shared: &Arc<Shared<W>>,
    spec: &RequestSpec,
    control: &Arc<RequestControl>,
) -> Result<(), String>
where
    W: Write + Send + 'static,
{
    let RequestSpec::Command(spec) = spec else {
        let RequestSpec::Search(spec) = spec else {
            unreachable!()
        };
        return execute_search(shared, spec, control);
    };
    let mut command = match spec.shell.as_str() {
        "bash" => {
            let mut command = Command::new("bash");
            command.args(["--noprofile", "--norc", "-c", &spec.command]);
            command
        }
        "sh" => {
            let mut command = Command::new("sh");
            command.args(["-c", &spec.command]);
            command
        }
        "login" => {
            let login_shell = spec.login_shell.as_deref().unwrap_or("/bin/sh");
            let metadata =
                std::fs::metadata(login_shell).map_err(|_| "login-shell-unavailable".to_owned())?;
            if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
                return Err("login-shell-unavailable".to_owned());
            }
            let mut command = Command::new(login_shell);
            command.args(["-c", &spec.command]);
            command
        }
        _ => return Err("unsupported-shell".to_owned()),
    };
    command
        .current_dir(&spec.cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: setpgid is async-signal-safe and does not retain pointers.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            });
        }
    }
    let mut child = command
        .spawn()
        .map_err(|_| "command-spawn-failed".to_owned())?;
    let pid = child
        .id()
        .try_into()
        .map_err(|_| "command-pid-invalid".to_owned())?;
    control.process_group.store(pid, Ordering::Release);
    if control.cancelled.load(Ordering::Acquire) {
        control.cancel();
    }

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "stdout-pipe-missing".to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "stderr-pipe-missing".to_owned())?;
    let request_id = spec.request_id;
    let stdout_limit = spec.stdout_limit;
    let stderr_limit = spec.stderr_limit;
    let stdout_shared = Arc::clone(shared);
    let stdout_control = Arc::clone(control);
    let stop_sending = Arc::new(AtomicBool::new(false));
    let stdout_state = Arc::new(StreamDrainState::new(Arc::clone(&stop_sending)));
    let stdout_state_thread = Arc::clone(&stdout_state);
    let stdout_thread = thread::spawn(move || {
        drain_stream(
            stdout_shared,
            request_id,
            FrameKind::Stdout,
            stdout,
            stdout_limit,
            stdout_control,
            stdout_state_thread,
        )
    });
    let stderr_shared = Arc::clone(shared);
    let stderr_control = Arc::clone(control);
    let stderr_state = Arc::new(StreamDrainState::new(Arc::clone(&stop_sending)));
    let stderr_state_thread = Arc::clone(&stderr_state);
    let stderr_thread = thread::spawn(move || {
        drain_stream(
            stderr_shared,
            request_id,
            FrameKind::Stderr,
            stderr,
            stderr_limit,
            stderr_control,
            stderr_state_thread,
        )
    });
    let stdin_thread = child.stdin.take().map(|stdin| {
        let input = spec.stdin.clone();
        thread::spawn(move || write_stdin(stdin, &input))
    });
    let watchdog_done = Arc::new((Mutex::new(false), Condvar::new()));
    let timed_out = Arc::new(AtomicBool::new(false));
    let timeout = spec.timeout;
    let watchdog = if timeout.is_zero() {
        None
    } else {
        let watchdog_done = Arc::clone(&watchdog_done);
        let watchdog_control = Arc::clone(control);
        let watchdog_timed_out = Arc::clone(&timed_out);
        Some(thread::spawn(move || {
            let (done_lock, done_signal) = &*watchdog_done;
            let done = done_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let (done, _) = done_signal
                .wait_timeout_while(done, timeout, |done| !*done)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !*done {
                watchdog_timed_out.store(true, Ordering::Release);
                watchdog_control.cancel();
            }
        }))
    };
    let status = child.wait().map_err(|_| "command-wait-failed".to_owned())?;
    let (done_lock, done_signal) = &*watchdog_done;
    if let Ok(mut done) = done_lock.lock() {
        *done = true;
        done_signal.notify_one();
    }
    if let Some(watchdog) = watchdog {
        let _ = watchdog.join();
    }
    if let Some(stdin_thread) = stdin_thread {
        let _ = stdin_thread.join();
    }

    // A shell parent can exit while a long-lived child still owns one of the
    // capture pipes.  Normal commands have no remaining process group, so wait
    // for their finite output to close completely.  If a descendant remains in
    // this request's process group, bound the drain and complete the request;
    // the continuation bit makes that boundary explicit to the caller.
    let process_group_alive = process_group_exists(control.process_group.load(Ordering::Acquire));
    if process_group_alive {
        let mut drain_deadline = Instant::now() + DESCENDANT_DRAIN_GRACE;
        let mut timeout_cleanup_observed = false;
        while !(stdout_state.pipe_closed.load(Ordering::Acquire)
            && stderr_state.pipe_closed.load(Ordering::Acquire))
            && Instant::now() < drain_deadline
        {
            if timed_out.load(Ordering::Acquire) && !timeout_cleanup_observed {
                timeout_cleanup_observed = true;
                let timeout_cleanup_deadline =
                    Instant::now() + TERM_GRACE + TIMEOUT_PIPE_CLOSE_GRACE;
                if timeout_cleanup_deadline > drain_deadline {
                    drain_deadline = timeout_cleanup_deadline;
                }
            }
            thread::sleep(Duration::from_millis(5));
        }
    } else {
        while !(stdout_state.pipe_closed.load(Ordering::Acquire)
            && stderr_state.pipe_closed.load(Ordering::Acquire))
        {
            thread::sleep(Duration::from_millis(5));
        }
    }
    let pipes_closed = stdout_state.pipe_closed.load(Ordering::Acquire)
        && stderr_state.pipe_closed.load(Ordering::Acquire);
    let remote_process_may_continue = process_group_alive || !pipes_closed;
    let status_code = exit_status(status);
    if pipes_closed {
        // All finite output has reached EOF.  Join before EXIT so the final
        // stream frames are guaranteed to precede completion.
        let _ = stdout_thread.join();
        let _ = stderr_thread.join();
    } else {
        // The descendant owns a pipe.  Stop emitting frames, complete the
        // request, and let the reader threads drain quietly in the background.
        stop_sending.store(true, Ordering::Release);
    }
    let payload = format!(
        "{status_code}\n{}\n{}\n{}\n{}\n",
        u8::from(stdout_state.truncated.load(Ordering::Acquire)),
        u8::from(stderr_state.truncated.load(Ordering::Acquire)),
        u8::from(remote_process_may_continue),
        u8::from(timed_out.load(Ordering::Acquire))
    )
    .into_bytes();
    let _ = send_frame(
        shared,
        Frame {
            kind: FrameKind::Exit,
            request_id: spec.request_id,
            payload,
        },
    );
    // On the continuation path the unjoined handles are dropped automatically,
    // detaching the blocked readers without retaining the request worker.
    control.process_group.store(0, Ordering::Release);
    Ok(())
}

fn execute_search<W>(
    shared: &Arc<Shared<W>>,
    spec: &SearchSpec,
    control: &Arc<RequestControl>,
) -> Result<(), String>
where
    W: Write + Send + 'static,
{
    let metadata = std::fs::metadata(&spec.root).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => "search-root-not-found".to_owned(),
        io::ErrorKind::PermissionDenied => "search-root-permission-denied".to_owned(),
        _ => "search-root-metadata-failed".to_owned(),
    })?;
    if !metadata.is_dir() {
        return Err("search-root-not-directory".to_owned());
    }
    let globs = compile_globs(&spec.globs)?;
    let finder = memmem::Finder::new(&spec.query);
    let started = Instant::now();
    let deadline = (!spec.timeout.is_zero()).then(|| started + spec.timeout);
    let mut paths = vec![spec.root.clone()];
    let mut stdout_seen = 0u64;
    let mut stdout_truncated = false;
    let mut matched = 0usize;
    let mut timed_out = false;

    while let Some(directory) = paths.pop() {
        if control.cancelled.load(Ordering::Acquire) {
            break;
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            timed_out = true;
            break;
        }
        let mut entries = std::fs::read_dir(&directory)
            .map_err(|_| "search-directory-read-failed".to_owned())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "search-directory-read-failed".to_owned())?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries.into_iter().rev() {
            if control.cancelled.load(Ordering::Acquire) {
                break;
            }
            let file_type = entry
                .file_type()
                .map_err(|_| "search-entry-metadata-failed".to_owned())?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                paths.push(entry.path());
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let relative = entry
                .path()
                .strip_prefix(&spec.root)
                .map_err(|_| "search-path-escaped-root".to_owned())?
                .to_owned();
            if !matches_globs(&globs, &spec.globs, &relative) {
                continue;
            }
            let outcome = search_file(
                &entry.path(),
                &spec.query,
                &finder,
                spec.binary,
                spec.max_results.saturating_sub(matched),
                usize::try_from(spec.stdout_limit.saturating_sub(stdout_seen))
                    .unwrap_or(usize::MAX),
                control,
                deadline,
            )?;
            timed_out |= outcome.timed_out;
            if outcome.output_truncated {
                stdout_truncated = true;
            }
            for found in outcome.matches {
                let record =
                    encode_search_match(&entry.path(), found.line, found.column, &found.content)?;
                let record_len = u64::try_from(record.len()).unwrap_or(u64::MAX);
                if record_len > spec.stdout_limit.saturating_sub(stdout_seen) {
                    stdout_truncated = true;
                    break;
                }
                send_stream_frame(
                    shared,
                    Frame {
                        kind: FrameKind::Stdout,
                        request_id: spec.request_id,
                        payload: record,
                    },
                    &control.cancelled,
                )
                .map_err(|_| "search-output-write-failed".to_owned())?;
                stdout_seen = stdout_seen.saturating_add(record_len);
                matched = matched.saturating_add(1);
                if matched >= spec.max_results {
                    break;
                }
            }
            if matched >= spec.max_results || stdout_truncated || timed_out {
                break;
            }
        }
        if matched >= spec.max_results || stdout_truncated || timed_out {
            break;
        }
    }

    let cancelled = control.cancelled.load(Ordering::Acquire);
    let status = if cancelled { 130 } else { 0 };
    let payload = format!(
        "{status}\n{}\n0\n0\n{}\n",
        u8::from(stdout_truncated),
        u8::from(timed_out)
    )
    .into_bytes();
    send_frame(
        shared,
        Frame {
            kind: FrameKind::Exit,
            request_id: spec.request_id,
            payload,
        },
    )
    .map_err(|_| "search-exit-write-failed".to_owned())
}

fn validate_glob(glob: &str) -> Result<(), String> {
    GlobBuilder::new(glob)
        .literal_separator(true)
        .build()
        .map(|_| ())
        .map_err(|_| "invalid-search-glob".to_owned())
}

fn compile_globs(globs: &[String]) -> Result<GlobSet, String> {
    let mut builder = GlobSetBuilder::new();
    for glob in globs {
        builder.add(
            GlobBuilder::new(glob)
                .literal_separator(true)
                .build()
                .map_err(|_| "invalid-search-glob".to_owned())?,
        );
    }
    builder
        .build()
        .map_err(|_| "invalid-search-glob".to_owned())
}

fn matches_globs(globs: &GlobSet, patterns: &[String], relative: &Path) -> bool {
    patterns.is_empty()
        || globs.is_match(relative)
        || relative
            .file_name()
            .is_some_and(|name| globs.is_match(Path::new(name)))
}

struct FileSearchOutcome {
    matches: Vec<FoundMatch>,
    output_truncated: bool,
    timed_out: bool,
}

struct FoundMatch {
    line: u64,
    column: u64,
    content: Vec<u8>,
}

fn search_file(
    path: &Path,
    query: &[u8],
    finder: &memmem::Finder<'_>,
    binary: bool,
    max_results: usize,
    content_budget: usize,
    control: &RequestControl,
    deadline: Option<Instant>,
) -> Result<FileSearchOutcome, String> {
    if max_results == 0 {
        return Ok(FileSearchOutcome {
            matches: Vec::new(),
            output_truncated: false,
            timed_out: false,
        });
    }
    let file = std::fs::File::open(path).map_err(|error| match error.kind() {
        io::ErrorKind::PermissionDenied => "search-file-permission-denied".to_owned(),
        _ => "search-file-open-failed".to_owned(),
    })?;
    let mut reader = BufReader::with_capacity(STREAM_BUFFER_BYTES, file);
    let mut matches = Vec::new();
    let mut line = Vec::new();
    let mut overlap = Vec::with_capacity(query.len().saturating_sub(1));
    let mut boundary = Vec::with_capacity(query.len().saturating_sub(1).saturating_mul(2));
    let mut line_number = 1u64;
    let mut line_bytes = 0usize;
    let mut first_column = None;
    let mut binary_file = false;
    let mut output_truncated = false;
    let mut timed_out = false;
    let content_budget = content_budget.min(u32::MAX as usize);
    let mut retained_content = 0usize;

    loop {
        if control.cancelled.load(Ordering::Acquire) {
            break;
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            timed_out = true;
            break;
        }
        let buffer = reader
            .fill_buf()
            .map_err(|_| "search-file-read-failed".to_owned())?;
        if buffer.is_empty() {
            if line_bytes > 0 {
                finish_search_line(
                    &mut matches,
                    line_number,
                    first_column,
                    &line,
                    line_bytes,
                    content_budget,
                    &mut retained_content,
                    max_results,
                    &mut output_truncated,
                );
            }
            break;
        }
        let consumed = buffer.len();
        binary_file |= memchr(0, buffer).is_some();
        let mut segment_start = 0usize;
        for newline in memchr_iter(b'\n', buffer) {
            scan_search_segment(
                &buffer[segment_start..newline],
                query.len(),
                finder,
                &mut line,
                &mut line_bytes,
                &mut first_column,
                &mut overlap,
                &mut boundary,
                content_budget.saturating_sub(retained_content),
            );
            finish_search_line(
                &mut matches,
                line_number,
                first_column,
                &line,
                line_bytes,
                content_budget,
                &mut retained_content,
                max_results,
                &mut output_truncated,
            );
            if binary && (matches.len() >= max_results || output_truncated) {
                break;
            }
            line.clear();
            overlap.clear();
            boundary.clear();
            line_bytes = 0;
            line_number = line_number.saturating_add(1);
            first_column = None;
            segment_start = newline.saturating_add(1);
        }
        if !(binary && (matches.len() >= max_results || output_truncated)) {
            scan_search_segment(
                &buffer[segment_start..],
                query.len(),
                finder,
                &mut line,
                &mut line_bytes,
                &mut first_column,
                &mut overlap,
                &mut boundary,
                content_budget.saturating_sub(retained_content),
            );
        }
        reader.consume(consumed);
        if binary && (matches.len() >= max_results || output_truncated) {
            break;
        }
    }
    if binary_file && !binary {
        matches.clear();
        output_truncated = false;
    }
    Ok(FileSearchOutcome {
        matches,
        output_truncated,
        timed_out,
    })
}

#[allow(clippy::too_many_arguments)]
fn scan_search_segment(
    segment: &[u8],
    query_length: usize,
    finder: &memmem::Finder<'_>,
    line: &mut Vec<u8>,
    line_bytes: &mut usize,
    first_column: &mut Option<usize>,
    overlap: &mut Vec<u8>,
    boundary: &mut Vec<u8>,
    line_content_budget: usize,
) {
    let retained = line_content_budget.saturating_sub(line.len());
    line.extend_from_slice(&segment[..segment.len().min(retained)]);

    if first_column.is_none() {
        if !overlap.is_empty() {
            boundary.clear();
            boundary.extend_from_slice(overlap);
            boundary
                .extend_from_slice(&segment[..segment.len().min(query_length.saturating_sub(1))]);
            if let Some(index) = finder.find(boundary)
                && index < overlap.len()
                && index.saturating_add(query_length) > overlap.len()
            {
                *first_column = Some(
                    line_bytes
                        .saturating_sub(overlap.len())
                        .saturating_add(index)
                        .saturating_add(1),
                );
            }
        }
        if first_column.is_none()
            && let Some(index) = finder.find(segment)
        {
            *first_column = Some(line_bytes.saturating_add(index).saturating_add(1));
        }
    }
    *line_bytes = line_bytes.saturating_add(segment.len());

    if first_column.is_some() {
        overlap.clear();
        return;
    }
    let overlap_limit = query_length.saturating_sub(1);
    if segment.len() >= overlap_limit {
        overlap.clear();
        overlap.extend_from_slice(&segment[segment.len().saturating_sub(overlap_limit)..]);
    } else {
        let excess = overlap
            .len()
            .saturating_add(segment.len())
            .saturating_sub(overlap_limit);
        if excess > 0 {
            overlap.drain(..excess);
        }
        overlap.extend_from_slice(segment);
    }
}

#[allow(clippy::too_many_arguments)]
fn finish_search_line(
    matches: &mut Vec<FoundMatch>,
    line: u64,
    column: Option<usize>,
    content: &[u8],
    actual_length: usize,
    content_budget: usize,
    retained_content: &mut usize,
    max_results: usize,
    output_truncated: &mut bool,
) {
    let Some(column) = column else { return };
    if matches.len() >= max_results {
        return;
    }
    if actual_length > content_budget.saturating_sub(*retained_content) {
        *output_truncated = true;
        return;
    }
    *retained_content = (*retained_content).saturating_add(actual_length);
    matches.push(FoundMatch {
        line,
        column: u64::try_from(column).unwrap_or(u64::MAX),
        content: content.to_vec(),
    });
}

fn encode_search_match(
    relative: &Path,
    line: u64,
    column: u64,
    content: &[u8],
) -> Result<Vec<u8>, String> {
    use std::os::unix::ffi::OsStrExt;

    let path = relative.as_os_str().as_bytes();
    let path_length = u32::try_from(path.len()).map_err(|_| "search-path-too-long".to_owned())?;
    let content_length =
        u32::try_from(content.len()).map_err(|_| "search-line-too-long".to_owned())?;
    let capacity = 5usize
        .checked_add(4 + 8 + 8 + 4)
        .and_then(|length| length.checked_add(path.len()))
        .and_then(|length| length.checked_add(content.len()))
        .ok_or_else(|| "search-record-too-large".to_owned())?;
    let mut record = Vec::with_capacity(capacity);
    record.extend_from_slice(b"CXSM1");
    record.extend_from_slice(&path_length.to_le_bytes());
    record.extend_from_slice(&line.to_le_bytes());
    record.extend_from_slice(&column.to_le_bytes());
    record.extend_from_slice(&content_length.to_le_bytes());
    record.extend_from_slice(path);
    record.extend_from_slice(content);
    Ok(record)
}

fn write_stdin(mut stdin: ChildStdin, input: &[u8]) -> bool {
    stdin.write_all(input).is_ok()
}

fn drain_stream<W, R>(
    shared: Arc<Shared<W>>,
    request_id: u64,
    kind: FrameKind,
    mut reader: R,
    limit: u64,
    control: Arc<RequestControl>,
    state: Arc<StreamDrainState>,
) -> bool
where
    W: Write + Send + 'static,
    R: Read,
{
    let chunk_size = STREAM_BUFFER_BYTES.min(shared.max_frame_bytes.max(1));
    let mut buffer = vec![0; chunk_size];
    let mut seen = 0u64;
    let mut truncated = false;
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) | Err(_) => {
                state.pipe_closed.store(true, Ordering::Release);
                break;
            }
            Ok(read) => read,
        };
        let remaining = limit.saturating_sub(seen);
        let allowed = remaining.min(read as u64) as usize;
        if allowed < read {
            truncated = true;
            state.truncated.store(true, Ordering::Release);
        }
        if allowed > 0
            && !state.stop_sending.load(Ordering::Acquire)
            && send_stream_frame(
                &shared,
                Frame {
                    kind,
                    request_id,
                    payload: buffer[..allowed].to_vec(),
                },
                &state.stop_sending,
            )
            .is_err()
        {
            break;
        }
        seen = seen.saturating_add(read as u64);
        if control.cancelled.load(Ordering::Acquire) {
            // Continue draining until the child closes the pipe so the worker
            // cannot leave a descendant holding the SSH channel open.
            continue;
        }
    }
    state.pipe_closed.store(true, Ordering::Release);
    truncated
}

fn exit_status(status: std::process::ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(code) = status.code() {
            return code;
        }
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    status.code().unwrap_or(1)
}

fn process_group_exists(process_group: i32) -> bool {
    if process_group <= 0 {
        return false;
    }
    #[cfg(unix)]
    {
        // SAFETY: kill with signal 0 only probes process-group existence.
        let result = unsafe { libc::kill(-process_group, 0) };
        result == 0 || io::Error::last_os_error().kind() == io::ErrorKind::PermissionDenied
    }
    #[cfg(not(unix))]
    {
        let _ = process_group;
        false
    }
}

fn terminate_process_group(process_group: i32) {
    if process_group <= 0 {
        return;
    }
    #[cfg(unix)]
    unsafe {
        let _ = libc::kill(-process_group, libc::SIGTERM);
        thread::sleep(TERM_GRACE);
        let _ = libc::kill(-process_group, libc::SIGKILL);
    }
}

fn machine_arch() -> String {
    #[cfg(unix)]
    {
        let mut value = std::mem::MaybeUninit::<libc::utsname>::uninit();
        // SAFETY: uname initializes the provided structure on success.
        if unsafe { libc::uname(value.as_mut_ptr()) } == 0 {
            // SAFETY: uname filled the structure and machine is NUL-terminated.
            let value = unsafe { value.assume_init() };
            let bytes = value.machine.as_ptr().cast::<u8>();
            let bytes = unsafe { std::slice::from_raw_parts(bytes, value.machine.len()) };
            let length = bytes
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(bytes.len());
            if let Ok(machine) = std::str::from_utf8(&bytes[..length])
                && !machine.is_empty()
            {
                return machine.to_owned();
            }
        }
    }
    std::env::consts::ARCH.to_owned()
}

fn lock_error<T>(_: std::sync::PoisonError<T>) -> io::Error {
    io::Error::other("helper synchronization lock poisoned")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vectorized_search_preserves_matches_across_read_buffers() {
        let query = b"needle";
        let finder = memmem::Finder::new(query);
        let mut line = Vec::new();
        let mut line_bytes = 0;
        let mut first_column = None;
        let mut overlap = Vec::new();
        let mut boundary = Vec::new();

        scan_search_segment(
            b"aaa nee",
            query.len(),
            &finder,
            &mut line,
            &mut line_bytes,
            &mut first_column,
            &mut overlap,
            &mut boundary,
            1024,
        );
        assert_eq!(first_column, None);
        scan_search_segment(
            b"dle z",
            query.len(),
            &finder,
            &mut line,
            &mut line_bytes,
            &mut first_column,
            &mut overlap,
            &mut boundary,
            1024,
        );

        assert_eq!(first_column, Some(5));
        assert_eq!(line_bytes, 12);
        assert_eq!(line, b"aaa needle z");
    }
}
