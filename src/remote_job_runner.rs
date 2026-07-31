use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::RngCore as _;

use crate::job_protocol::{
    JOB_RECORD_VERSION, JobControlRequest, JobControlResponse, JobId, JobLogEncoding, JobLogPage,
    JobLogsRequest, JobLogsResponse, JobRequestRecord, JobShell, JobState, JobStateRecord,
    ProcessIdentity,
};

const REQUEST_FILE: &str = "request";
const STATE_FILE: &str = "state";
const STDOUT_FILE: &str = "stdout.log";
const STDERR_FILE: &str = "stderr.log";
const LOCK_FILE: &str = "runner.lock";
const MAX_RECORD_BYTES: u64 = 16 * 1024 * 1024;
const TERM_GRACE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct JobStore {
    root: PathBuf,
}

impl JobStore {
    pub fn open() -> io::Result<Self> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
        Self::open_at(&home)
    }

    #[doc(hidden)]
    pub fn open_at(home: &Path) -> io::Result<Self> {
        validate_owned_directory(home, false)?;
        let mut current = home.to_path_buf();
        for (component, private) in [
            (".local", false),
            ("state", false),
            ("codex-ssh-bridge", true),
            ("jobs", true),
        ] {
            current.push(component);
            ensure_owned_directory(&current, private)?;
        }
        Ok(Self { root: current })
    }

    pub fn create(&self, request: &JobRequestRecord) -> io::Result<()> {
        validate_request(request)?;
        let job = self.job_path(&request.job_id);
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder.create(&job)?;
        validate_owned_directory(&job, true)?;

        let result = (|| {
            create_record(&job.join(REQUEST_FILE), request)?;
            create_private_file(&job.join(STDOUT_FILE))?;
            create_private_file(&job.join(STDERR_FILE))?;
            create_private_file(&job.join(LOCK_FILE))?;
            let state = starting_state(request)?;
            create_record(&job.join(STATE_FILE), &state)?;
            sync_directory(&job)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&job);
        }
        result
    }

    pub fn status(&self, id: &JobId) -> io::Result<JobStateRecord> {
        let job = self.open_job(id)?;
        read_record(&job.join(STATE_FILE))
    }

    pub fn logs(&self, request: &JobLogsRequest) -> io::Result<JobLogsResponse> {
        if request.max_bytes == 0 || request.max_bytes > crate::job_protocol::MAX_JOB_LOG_PAGE_BYTES
        {
            return Err(invalid_data("invalid job log page size"));
        }
        let job = self.open_job(&request.job_id)?;
        let state: JobStateRecord = read_record(&job.join(STATE_FILE))?;
        let stdout_budget = request.max_bytes;
        let stdout = read_log_page(
            &job.join(STDOUT_FILE),
            request.stdout_offset,
            stdout_budget,
            state.stdout_observed_bytes,
            state.stdout_truncated,
        )?;
        let stdout_raw = decoded_page_len(&stdout)?;
        let stderr = read_log_page(
            &job.join(STDERR_FILE),
            request.stderr_offset,
            request.max_bytes.saturating_sub(stdout_raw),
            state.stderr_observed_bytes,
            state.stderr_truncated,
        )?;
        Ok(JobLogsResponse {
            job_id: request.job_id.clone(),
            state: state.state,
            stdout,
            stderr,
        })
    }

    fn request(&self, id: &JobId) -> io::Result<JobRequestRecord> {
        let job = self.open_job(id)?;
        read_record(&job.join(REQUEST_FILE))
    }

    fn replace_state(&self, state: &JobStateRecord) -> io::Result<()> {
        let job = self.open_job(&state.job_id)?;
        replace_record(&job, STATE_FILE, state)
    }

    fn lock(&self, id: &JobId) -> io::Result<File> {
        let job = self.open_job(id)?;
        let file = open_private(&job.join(LOCK_FILE), false, false)?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(file)
    }

    fn open_job(&self, id: &JobId) -> io::Result<PathBuf> {
        let id = JobId::parse(id.as_str()).map_err(|_| invalid_data("invalid job id"))?;
        let path = self.root.join(id.as_str());
        validate_owned_directory(&path, true)?;
        Ok(path)
    }

    fn job_path(&self, id: &JobId) -> PathBuf {
        self.root.join(id.as_str())
    }
}

pub fn execute_control(request: JobControlRequest) -> io::Result<JobControlResponse> {
    let store = JobStore::open()?;
    match request {
        JobControlRequest::Start(request) => {
            let state = start_job(&store, request)?;
            Ok(JobControlResponse::Started(state))
        }
        JobControlRequest::Status { job_id } => {
            Ok(JobControlResponse::Status(store.status(&job_id)?))
        }
        JobControlRequest::Logs(request) => Ok(JobControlResponse::Logs(store.logs(&request)?)),
        JobControlRequest::Cancel { .. }
        | JobControlRequest::List { .. }
        | JobControlRequest::Delete { .. } => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "remote job control is not implemented",
        )),
    }
}

fn start_job(store: &JobStore, request: JobRequestRecord) -> io::Result<JobStateRecord> {
    store.create(&request)?;
    let executable = std::env::current_exe()?;
    let mut command = Command::new(executable);
    command
        .args(["job-runner", request.job_id.as_str()])
        .env_remove("CODEX_SSH_HELPER_PATH")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() >= 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    }
    command.spawn()?;

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let state = store.status(&request.job_id)?;
        if state.state != JobState::Starting {
            return Ok(state);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "remote job runner readiness timed out",
            ));
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[doc(hidden)]
pub fn run_job_at(home: &Path, id: &JobId) -> io::Result<()> {
    run_job(JobStore::open_at(home)?, id)
}

pub fn run_job_from_environment(id: &JobId) -> io::Result<()> {
    run_job(JobStore::open()?, id)
}

fn run_job(store: JobStore, id: &JobId) -> io::Result<()> {
    let _lock = store.lock(id)?;
    let request = store.request(id)?;
    let stdin = STANDARD
        .decode(request.stdin_base64.as_bytes())
        .map_err(|_| invalid_data("job stdin is not canonical Base64"))?;
    if STANDARD.encode(&stdin) != request.stdin_base64 {
        return Err(invalid_data("job stdin is not canonical Base64"));
    }

    let job = store.open_job(id)?;
    let stdout = open_private(&job.join(STDOUT_FILE), true, true)?;
    let stderr = open_private(&job.join(STDERR_FILE), true, true)?;
    let mut command = shell_command(&request.shell)?;
    command
        .current_dir(&request.cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    }
    command.arg(&request.command);
    let mut child = command.spawn()?;
    let child_pid = i32::try_from(child.id()).map_err(|_| invalid_data("child pid overflow"))?;
    if let Some(mut input) = child.stdin.take() {
        input.write_all(&stdin)?;
    }

    let mut state = store.status(id)?;
    state.state = JobState::Running;
    state.boot_id = boot_id()?;
    state.runner = Some(process_identity(std::process::id())?);
    state.command_group = Some(process_identity(child.id())?);
    state.started_unix_ms = Some(now_ms()?);
    store.replace_state(&state)?;

    let quota = Arc::new(AtomicU64::new(0));
    let stdout_stats = Arc::new(DrainStats::default());
    let stderr_stats = Arc::new(DrainStats::default());
    let stdout_thread = drain_stream(
        child
            .stdout
            .take()
            .ok_or_else(|| invalid_data("missing job stdout"))?,
        stdout,
        Arc::clone(&quota),
        request.max_output_bytes,
        Arc::clone(&stdout_stats),
    );
    let stderr_thread = drain_stream(
        child
            .stderr
            .take()
            .ok_or_else(|| invalid_data("missing job stderr"))?,
        stderr,
        quota,
        request.max_output_bytes,
        Arc::clone(&stderr_stats),
    );

    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if request
            .timeout_ms
            .is_some_and(|milliseconds| started.elapsed() >= Duration::from_millis(milliseconds))
        {
            timed_out = true;
            terminate_verified_group(child_pid, libc::SIGTERM);
            break wait_after_signal(&mut child, child_pid)?;
        } else {
            thread::sleep(Duration::from_millis(5));
        }
    };

    join_drain(stdout_thread)?;
    join_drain(stderr_thread)?;
    state.state = if timed_out {
        JobState::TimedOut
    } else if status.success() {
        JobState::Succeeded
    } else {
        JobState::Failed
    };
    state.exit_code = status.code();
    state.signal = status.signal();
    state.finished_unix_ms = Some(now_ms()?);
    state.stdout_retained_bytes = stdout_stats.retained.load(Ordering::Acquire);
    state.stdout_observed_bytes = stdout_stats.observed.load(Ordering::Acquire);
    state.stderr_retained_bytes = stderr_stats.retained.load(Ordering::Acquire);
    state.stderr_observed_bytes = stderr_stats.observed.load(Ordering::Acquire);
    state.stdout_truncated = state.stdout_retained_bytes < state.stdout_observed_bytes;
    state.stderr_truncated = state.stderr_retained_bytes < state.stderr_observed_bytes;
    store.replace_state(&state)
}

fn shell_command(shell: &JobShell) -> io::Result<Command> {
    let (program, arguments): (&str, &[&str]) = match shell {
        JobShell::Bash => ("bash", &["--noprofile", "--norc", "-c"]),
        JobShell::Sh => ("sh", &["-c"]),
        JobShell::Login { path } => {
            if !path.starts_with('/') || path.as_bytes().contains(&0) {
                return Err(invalid_data("invalid login shell path"));
            }
            let mut command = Command::new(path);
            command.arg("-lc");
            return Ok(command);
        }
    };
    let mut command = Command::new(program);
    command.args(arguments);
    Ok(command)
}

#[derive(Default)]
struct DrainStats {
    observed: AtomicU64,
    retained: AtomicU64,
}

fn drain_stream<R: Read + Send + 'static>(
    mut reader: R,
    mut output: File,
    quota: Arc<AtomicU64>,
    maximum: u64,
    stats: Arc<DrainStats>,
) -> thread::JoinHandle<io::Result<()>> {
    thread::spawn(move || {
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                output.sync_data()?;
                return Ok(());
            }
            stats.observed.fetch_add(count as u64, Ordering::AcqRel);
            let retained = reserve_quota(&quota, maximum, count as u64) as usize;
            if retained != 0 {
                output.write_all(&buffer[..retained])?;
                stats.retained.fetch_add(retained as u64, Ordering::AcqRel);
            }
        }
    })
}

fn reserve_quota(quota: &AtomicU64, maximum: u64, wanted: u64) -> u64 {
    let mut used = quota.load(Ordering::Acquire);
    loop {
        let retained = wanted.min(maximum.saturating_sub(used));
        let next = used.saturating_add(retained);
        match quota.compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return retained,
            Err(observed) => used = observed,
        }
    }
}

fn join_drain(handle: thread::JoinHandle<io::Result<()>>) -> io::Result<()> {
    handle
        .join()
        .map_err(|_| invalid_data("job output drain panicked"))?
}

fn terminate_verified_group(process_group: i32, signal: i32) {
    if process_group > 0 {
        unsafe {
            libc::kill(-process_group, signal);
        }
    }
}

fn wait_after_signal(
    child: &mut std::process::Child,
    process_group: i32,
) -> io::Result<std::process::ExitStatus> {
    let deadline = Instant::now() + TERM_GRACE;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            terminate_verified_group(process_group, libc::SIGKILL);
            return child.wait();
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn starting_state(request: &JobRequestRecord) -> io::Result<JobStateRecord> {
    Ok(JobStateRecord {
        version: JOB_RECORD_VERSION,
        job_id: request.job_id.clone(),
        state: JobState::Starting,
        boot_id: boot_id()?,
        runner: None,
        command_group: None,
        created_unix_ms: request.created_unix_ms,
        started_unix_ms: None,
        finished_unix_ms: None,
        exit_code: None,
        signal: None,
        stdout_retained_bytes: 0,
        stdout_observed_bytes: 0,
        stderr_retained_bytes: 0,
        stderr_observed_bytes: 0,
        stdout_truncated: false,
        stderr_truncated: false,
    })
}

fn validate_request(request: &JobRequestRecord) -> io::Result<()> {
    if request.version != JOB_RECORD_VERSION
        || request.command.is_empty()
        || request.command.as_bytes().contains(&0)
        || !request.cwd.starts_with('/')
        || request.cwd.as_bytes().contains(&0)
        || request.timeout_ms == Some(0)
        || request.max_output_bytes == 0
        || request.label.as_ref().is_some_and(|label| {
            label.len() > crate::job_protocol::MAX_JOB_LABEL_BYTES || label.as_bytes().contains(&0)
        })
    {
        return Err(invalid_data("invalid job request"));
    }
    JobId::parse(request.job_id.as_str()).map_err(|_| invalid_data("invalid job id"))?;
    let stdin = STANDARD
        .decode(request.stdin_base64.as_bytes())
        .map_err(|_| invalid_data("job stdin is not Base64"))?;
    if STANDARD.encode(stdin) != request.stdin_base64 {
        return Err(invalid_data("job stdin is not canonical Base64"));
    }
    Ok(())
}

fn read_log_page(
    path: &Path,
    offset: u64,
    maximum: usize,
    observed_bytes: u64,
    truncated: bool,
) -> io::Result<JobLogPage> {
    let mut file = open_private(path, false, false)?;
    let retained_bytes = file.metadata()?.len();
    if offset > retained_bytes {
        return Err(invalid_data("job log offset exceeds retained length"));
    }
    file.seek(SeekFrom::Start(offset))?;
    let wanted = maximum.min(usize::try_from(retained_bytes - offset).unwrap_or(usize::MAX));
    let mut bytes = vec![0_u8; wanted];
    file.read_exact(&mut bytes)?;
    let next_offset = offset
        .checked_add(bytes.len() as u64)
        .ok_or_else(|| invalid_data("job log offset overflow"))?;
    let (encoding, value) = match String::from_utf8(bytes.clone()) {
        Ok(value) => (JobLogEncoding::Utf8, value),
        Err(_) => (JobLogEncoding::Base64, STANDARD.encode(bytes)),
    };
    Ok(JobLogPage {
        encoding,
        value,
        next_offset,
        eof: next_offset == retained_bytes,
        retained_bytes,
        observed_bytes: observed_bytes.max(retained_bytes),
        truncated,
    })
}

fn decoded_page_len(page: &JobLogPage) -> io::Result<usize> {
    match page.encoding {
        JobLogEncoding::Utf8 => Ok(page.value.len()),
        JobLogEncoding::Base64 => STANDARD
            .decode(page.value.as_bytes())
            .map(|bytes| bytes.len())
            .map_err(|_| invalid_data("internal job log encoding is invalid")),
    }
}

fn create_record<T: serde::Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let mut file = create_private_file(path)?;
    serde_json::to_writer(&mut file, value).map_err(invalid_json)?;
    file.sync_all()
}

fn replace_record<T: serde::Serialize>(directory: &Path, name: &str, value: &T) -> io::Result<()> {
    let mut random = [0_u8; 8];
    rand::rng().fill_bytes(&mut random);
    let temporary = directory.join(format!(".{name}.{:016x}", u64::from_le_bytes(random)));
    let result = (|| {
        let mut file = create_private_file(&temporary)?;
        serde_json::to_writer(&mut file, value).map_err(invalid_json)?;
        file.sync_all()?;
        fs::rename(&temporary, directory.join(name))?;
        sync_directory(directory)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn read_record<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<T> {
    let file = open_private(path, false, false)?;
    if file.metadata()?.len() > MAX_RECORD_BYTES {
        return Err(invalid_data("job record exceeds size limit"));
    }
    serde_json::from_reader(file.take(MAX_RECORD_BYTES + 1)).map_err(invalid_json)
}

fn create_private_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

fn open_private(path: &Path, write: bool, append: bool) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(!write)
        .write(write)
        .append(append)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o177 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "insecure remote job file",
        ));
    }
    Ok(file)
}

fn ensure_owned_directory(path: &Path, private: bool) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_owned_directory(path, private),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            match builder.create(path) {
                Ok(()) => validate_owned_directory(path, private),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    validate_owned_directory(path, private)
                }
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

fn validate_owned_directory(path: &Path, private: bool) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let mode = metadata.permissions().mode();
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || mode & 0o022 != 0
        || private && mode & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "insecure remote job directory",
        ));
    }
    Ok(())
}

fn sync_directory(path: &Path) -> io::Result<()> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?
        .sync_all()
}

fn boot_id() -> io::Result<String> {
    let value = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let value = value.trim();
    if value.len() != 36 || value.as_bytes().contains(&0) {
        return Err(invalid_data("invalid kernel boot id"));
    }
    Ok(value.to_owned())
}

fn process_identity(pid: u32) -> io::Result<ProcessIdentity> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let close = stat
        .rfind(')')
        .ok_or_else(|| invalid_data("invalid proc stat"))?;
    let start_ticks = stat[close + 1..]
        .split_ascii_whitespace()
        .nth(19)
        .ok_or_else(|| invalid_data("proc stat lacks start time"))?
        .parse::<u64>()
        .map_err(|_| invalid_data("invalid proc start time"))?;
    Ok(ProcessIdentity {
        pid: i32::try_from(pid).map_err(|_| invalid_data("process id overflow"))?,
        start_ticks,
    })
}

fn now_ms() -> io::Result<u64> {
    u64::try_from(
        SystemTime::UNIX_EPOCH
            .elapsed()
            .map_err(|_| invalid_data("system clock precedes epoch"))?
            .as_millis(),
    )
    .map_err(|_| invalid_data("system time overflow"))
}

fn invalid_json(error: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
