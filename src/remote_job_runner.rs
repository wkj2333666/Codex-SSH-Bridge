use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
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
const CANCEL_FILE: &str = "cancel.requested";
const MAX_RECORD_BYTES: u64 = 16 * 1024 * 1024;
const TERM_GRACE: Duration = Duration::from_secs(5);
const CONTROL_WAIT_GRACE: Duration = Duration::from_secs(6);
const JOB_RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
const MAX_LIST_JOBS: usize = 1_000;
const RETENTION_BUDGET: usize = 32;
const READINESS: &[u8] = b"READY\n";
const READINESS_ENV: &str = "CODEX_SSH_JOB_READINESS";

#[derive(Debug, Clone)]
pub struct JobStore {
    root: Arc<OwnedFd>,
    uid: libc::uid_t,
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
        let uid = unsafe { libc::geteuid() };
        let mut current = open_directory_path(home, uid, false)?;
        for (component, private) in [
            (".local", false),
            ("state", false),
            ("codex-ssh-bridge", true),
            ("jobs", true),
        ] {
            current = ensure_directory_at(current.as_raw_fd(), component, uid, private)?;
        }
        Ok(Self {
            root: Arc::new(current),
            uid,
        })
    }

    pub fn create(&self, request: &JobRequestRecord) -> io::Result<()> {
        validate_request(request)?;
        let id = checked_id(&request.job_id)?;
        mkdir_at(self.root.as_raw_fd(), &id, 0o700)?;
        let job = open_directory_at(self.root.as_raw_fd(), &id, self.uid, true)?;

        let result = (|| {
            create_record_at(job.as_raw_fd(), REQUEST_FILE, request, self.uid)?;
            create_private_file_at(job.as_raw_fd(), STDOUT_FILE, self.uid)?;
            create_private_file_at(job.as_raw_fd(), STDERR_FILE, self.uid)?;
            create_private_file_at(job.as_raw_fd(), LOCK_FILE, self.uid)?;
            let state = starting_state(request)?;
            create_record_at(job.as_raw_fd(), STATE_FILE, &state, self.uid)?;
            sync_fd(job.as_raw_fd())
        })();
        if result.is_err() {
            cleanup_job_files(job.as_raw_fd());
            drop(job);
            let _ = unlink_at(self.root.as_raw_fd(), &id, libc::AT_REMOVEDIR);
        }
        result
    }

    pub fn status(&self, id: &JobId) -> io::Result<JobStateRecord> {
        let state = self.read_state(id)?;
        self.reconcile_state(state)
    }

    pub fn logs(&self, request: &JobLogsRequest) -> io::Result<JobLogsResponse> {
        if request.max_bytes == 0 || request.max_bytes > crate::job_protocol::MAX_JOB_LOG_PAGE_BYTES
        {
            return Err(invalid_data("invalid job log page size"));
        }
        let job = self.open_job(&request.job_id)?;
        let state = self.status(&request.job_id)?;
        let stdout_budget = request.max_bytes;
        let stdout = read_log_page_at(
            job.as_raw_fd(),
            STDOUT_FILE,
            request.stdout_offset,
            stdout_budget,
            state.stdout_observed_bytes,
            state.stdout_truncated,
            self.uid,
        )?;
        let stdout_raw = decoded_page_len(&stdout)?;
        let stderr = read_log_page_at(
            job.as_raw_fd(),
            STDERR_FILE,
            request.stderr_offset,
            request.max_bytes.saturating_sub(stdout_raw),
            state.stderr_observed_bytes,
            state.stderr_truncated,
            self.uid,
        )?;
        Ok(JobLogsResponse {
            job_id: request.job_id.clone(),
            state: state.state,
            stdout,
            stderr,
        })
    }

    pub fn read_state(&self, id: &JobId) -> io::Result<JobStateRecord> {
        let job = self.open_job(id)?;
        let state: JobStateRecord = read_record_at(job.as_raw_fd(), STATE_FILE, self.uid)?;
        if state.version != JOB_RECORD_VERSION || &state.job_id != id {
            return Err(invalid_data("invalid job state record"));
        }
        Ok(state)
    }

    pub fn replace_state(&self, id: &JobId, state: &JobStateRecord) -> io::Result<()> {
        if state.version != JOB_RECORD_VERSION || &state.job_id != id {
            return Err(invalid_data("invalid job state replacement"));
        }
        let job = self.open_job(id)?;
        replace_record_at(job.as_raw_fd(), STATE_FILE, state, self.uid)
    }

    pub fn list(&self, max_jobs: usize) -> io::Result<Vec<crate::job_protocol::JobSummary>> {
        if max_jobs == 0 || max_jobs > MAX_LIST_JOBS {
            return Err(invalid_data("invalid remote job list limit"));
        }
        let mut jobs = Vec::new();
        for name in directory_names(self.root.as_raw_fd())? {
            let Ok(id) = JobId::parse(&name) else {
                continue;
            };
            let state = self.status(&id)?;
            let request = self.request(&id)?;
            jobs.push(crate::job_protocol::JobSummary {
                job_id: id,
                label: request.label,
                state: state.state,
                cwd: request.cwd,
                created_unix_ms: state.created_unix_ms,
                started_unix_ms: state.started_unix_ms,
                finished_unix_ms: state.finished_unix_ms,
                exit_code: state.exit_code,
                signal: state.signal,
            });
        }
        jobs.sort_by(|left, right| {
            right
                .created_unix_ms
                .cmp(&left.created_unix_ms)
                .then_with(|| right.job_id.as_str().cmp(left.job_id.as_str()))
        });
        jobs.truncate(max_jobs);
        Ok(jobs)
    }

    pub fn delete_terminal(&self, id: &JobId) -> io::Result<()> {
        let state = match self.status(id) {
            Ok(state) => state,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if !state.state.is_terminal() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "remote job is not terminal",
            ));
        }
        let id_name = checked_id(id)?;
        let job = self.open_job(id)?;
        let _lock = lock_job(job.as_raw_fd(), self.uid, false)?;
        for name in directory_names(job.as_raw_fd())? {
            if !matches!(
                name.as_str(),
                REQUEST_FILE | STATE_FILE | STDOUT_FILE | STDERR_FILE | LOCK_FILE | CANCEL_FILE
            ) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "remote job directory contains an unexpected entry",
                ));
            }
        }
        for name in [
            CANCEL_FILE,
            REQUEST_FILE,
            STATE_FILE,
            STDOUT_FILE,
            STDERR_FILE,
            LOCK_FILE,
        ] {
            unlink_at_if_exists(job.as_raw_fd(), name, 0)?;
        }
        drop(_lock);
        drop(job);
        unlink_at(self.root.as_raw_fd(), &id_name, libc::AT_REMOVEDIR)?;
        sync_fd(self.root.as_raw_fd())
    }

    pub fn collect_expired(&self, now_unix_ms: u64, budget: usize) -> io::Result<()> {
        if budget == 0 {
            return Ok(());
        }
        let mut removed = 0;
        for name in directory_names(self.root.as_raw_fd())? {
            if removed >= budget {
                break;
            }
            let Ok(id) = JobId::parse(&name) else {
                continue;
            };
            let state = self.status(&id)?;
            let expired = state.state.is_terminal()
                && state.finished_unix_ms.is_some_and(|finished| {
                    finished.saturating_add(JOB_RETENTION_MS) <= now_unix_ms
                });
            if expired {
                self.delete_terminal(&id)?;
                removed += 1;
            }
        }
        Ok(())
    }

    pub fn cancel(&self, id: &JobId) -> io::Result<JobStateRecord> {
        let state = self.status(id)?;
        if state.state.is_terminal() {
            return Ok(state);
        }
        let job = self.open_job(id)?;
        match create_private_file_at(job.as_raw_fd(), CANCEL_FILE, self.uid) {
            Ok(file) => {
                file.sync_all()?;
                sync_fd(job.as_raw_fd())?;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let deadline = Instant::now() + CONTROL_WAIT_GRACE;
        loop {
            let state = self.status(id)?;
            if state.state.is_terminal() {
                return Ok(state);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "remote job cancellation was not confirmed",
                ));
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn request(&self, id: &JobId) -> io::Result<JobRequestRecord> {
        let job = self.open_job(id)?;
        let request: JobRequestRecord = read_record_at(job.as_raw_fd(), REQUEST_FILE, self.uid)?;
        validate_request(&request)?;
        if &request.job_id != id {
            return Err(invalid_data("job request id mismatch"));
        }
        Ok(request)
    }

    fn lock(&self, id: &JobId) -> io::Result<File> {
        let job = self.open_job(id)?;
        lock_job(job.as_raw_fd(), self.uid, true)
    }

    fn open_job(&self, id: &JobId) -> io::Result<OwnedFd> {
        let id = checked_id(id)?;
        open_directory_at(self.root.as_raw_fd(), &id, self.uid, true)
    }

    fn reconcile_state(&self, mut state: JobStateRecord) -> io::Result<JobStateRecord> {
        if state.state.is_terminal() {
            return Ok(state);
        }
        let current_boot = boot_id()?;
        let boot_changed = state.boot_id != current_boot;
        let runner_missing = state.state == JobState::Running
            && state
                .runner
                .as_ref()
                .is_none_or(|runner| !process_matches(runner));
        if !boot_changed && !runner_missing {
            return Ok(state);
        }
        let job = self.open_job(&state.job_id)?;
        match lock_job(job.as_raw_fd(), self.uid, true) {
            Ok(_lock) => {
                let fresh: JobStateRecord = read_record_at(job.as_raw_fd(), STATE_FILE, self.uid)?;
                if fresh.state.is_terminal() {
                    return Ok(fresh);
                }
                if !boot_changed
                    && fresh.state == JobState::Running
                    && fresh.runner.as_ref().is_some_and(process_matches)
                {
                    return Ok(fresh);
                }
                state = fresh;
                state.state = JobState::Lost;
                state.finished_unix_ms = Some(now_ms()?);
                replace_record_at(job.as_raw_fd(), STATE_FILE, &state, self.uid)?;
                Ok(state)
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(state),
            Err(error) => Err(error),
        }
    }
}

pub fn execute_control(request: JobControlRequest) -> io::Result<JobControlResponse> {
    let store = JobStore::open()?;
    store.collect_expired(now_ms()?, RETENTION_BUDGET)?;
    match request {
        JobControlRequest::Start(request) => {
            let state = start_job(&store, request)?;
            Ok(JobControlResponse::Started(state))
        }
        JobControlRequest::Status { job_id } => {
            Ok(JobControlResponse::Status(store.status(&job_id)?))
        }
        JobControlRequest::Logs(request) => Ok(JobControlResponse::Logs(store.logs(&request)?)),
        JobControlRequest::Cancel { job_id } => {
            Ok(JobControlResponse::Cancelled(store.cancel(&job_id)?))
        }
        JobControlRequest::List { max_jobs } => {
            Ok(JobControlResponse::Listed(store.list(max_jobs)?))
        }
        JobControlRequest::Delete { job_id } => {
            store.delete_terminal(&job_id)?;
            Ok(JobControlResponse::Deleted { job_id })
        }
    }
}

fn start_job(store: &JobStore, request: JobRequestRecord) -> io::Result<JobStateRecord> {
    store.create(&request)?;
    let executable = std::env::current_exe()?;
    let mut command = Command::new(executable);
    command
        .args(["job-runner", request.job_id.as_str()])
        .env_remove("CODEX_SSH_HELPER_PATH")
        .env(READINESS_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
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
    let mut child = command.spawn()?;
    let mut readiness = child
        .stdout
        .take()
        .ok_or_else(|| invalid_data("remote job readiness pipe is missing"))?;
    wait_for_readiness(&mut readiness)?;
    let state = store.status(&request.job_id)?;
    if state.state != JobState::Running && !state.state.is_terminal() {
        return Err(invalid_data("remote job runner reported invalid readiness"));
    }
    Ok(state)
}

#[doc(hidden)]
pub fn run_job_at(home: &Path, id: &JobId) -> io::Result<()> {
    run_job(JobStore::open_at(home)?, id, false)
}

pub fn run_job_from_environment(id: &JobId) -> io::Result<()> {
    run_job(JobStore::open()?, id, true)
}

fn run_job(store: JobStore, id: &JobId, signal_ready: bool) -> io::Result<()> {
    let _lock = store.lock(id)?;
    let request = store.request(id)?;
    let stdin = STANDARD
        .decode(request.stdin_base64.as_bytes())
        .map_err(|_| invalid_data("job stdin is not canonical Base64"))?;
    if STANDARD.encode(&stdin) != request.stdin_base64 {
        return Err(invalid_data("job stdin is not canonical Base64"));
    }

    let job = store.open_job(id)?;
    let stdout = open_private_at(job.as_raw_fd(), STDOUT_FILE, true, true, store.uid)?;
    let stderr = open_private_at(job.as_raw_fd(), STDERR_FILE, true, true, store.uid)?;
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
    if let Some(mut input) = child.stdin.take() {
        input.write_all(&stdin)?;
    }

    let mut state = store.status(id)?;
    state.state = JobState::Running;
    state.boot_id = boot_id()?;
    state.runner = Some(process_identity(std::process::id())?);
    let command_identity = process_identity(child.id())?;
    state.command_group = Some(command_identity.clone());
    state.started_unix_ms = Some(now_ms()?);
    store.replace_state(id, &state)?;
    if signal_ready && std::env::var_os(READINESS_ENV).is_some() {
        let mut output = io::stdout().lock();
        output.write_all(READINESS)?;
        output.flush()?;
    }

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
    let mut cancelled = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if cancel_requested(job.as_raw_fd(), store.uid)? {
            cancelled = true;
            terminate_verified_group(&command_identity, libc::SIGTERM)?;
            break wait_after_signal(&mut child, &command_identity)?;
        } else if request
            .timeout_ms
            .is_some_and(|milliseconds| started.elapsed() >= Duration::from_millis(milliseconds))
        {
            timed_out = true;
            terminate_verified_group(&command_identity, libc::SIGTERM)?;
            break wait_after_signal(&mut child, &command_identity)?;
        } else {
            thread::sleep(Duration::from_millis(5));
        }
    };

    join_drain(stdout_thread)?;
    join_drain(stderr_thread)?;
    state.state = if cancelled {
        JobState::Cancelled
    } else if timed_out {
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
    store.replace_state(id, &state)
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

fn terminate_verified_group(identity: &ProcessIdentity, signal: i32) -> io::Result<bool> {
    if identity.pid <= 0 || !process_matches(identity) {
        return Ok(false);
    }
    let result = unsafe { libc::kill(-identity.pid, signal) };
    if result == 0 {
        Ok(true)
    } else {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(false)
        } else {
            Err(error)
        }
    }
}

fn wait_after_signal(
    child: &mut std::process::Child,
    identity: &ProcessIdentity,
) -> io::Result<std::process::ExitStatus> {
    let deadline = Instant::now() + TERM_GRACE;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            terminate_verified_group(identity, libc::SIGKILL)?;
            return child.wait();
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn cancel_requested(job: RawFd, uid: libc::uid_t) -> io::Result<bool> {
    match open_private_at(job, CANCEL_FILE, false, false, uid) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn wait_for_readiness(readiness: &mut std::process::ChildStdout) -> io::Result<()> {
    let mut poll = libc::pollfd {
        fd: readiness.as_raw_fd(),
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut poll, 1, 2_000) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if result == 0 {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "remote job runner readiness timed out",
        ));
    }
    let mut value = [0_u8; READINESS.len()];
    readiness.read_exact(&mut value)?;
    if value != READINESS {
        return Err(invalid_data("remote job runner readiness is invalid"));
    }
    Ok(())
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

fn read_log_page_at(
    directory: RawFd,
    name: &str,
    offset: u64,
    maximum: usize,
    observed_bytes: u64,
    truncated: bool,
    uid: libc::uid_t,
) -> io::Result<JobLogPage> {
    let mut file = open_private_at(directory, name, false, false, uid)?;
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

fn create_record_at<T: serde::Serialize>(
    directory: RawFd,
    name: &str,
    value: &T,
    uid: libc::uid_t,
) -> io::Result<()> {
    let mut file = create_private_file_at(directory, name, uid)?;
    serde_json::to_writer(&mut file, value).map_err(invalid_json)?;
    file.sync_all()
}

fn replace_record_at<T: serde::Serialize>(
    directory: RawFd,
    name: &str,
    value: &T,
    uid: libc::uid_t,
) -> io::Result<()> {
    let mut random = [0_u8; 8];
    rand::rng().fill_bytes(&mut random);
    let temporary = format!(".{name}.{:016x}", u64::from_le_bytes(random));
    let result = (|| {
        let mut file = create_private_file_at(directory, &temporary, uid)?;
        serde_json::to_writer(&mut file, value).map_err(invalid_json)?;
        file.sync_all()?;
        rename_at(directory, &temporary, directory, name)?;
        sync_fd(directory)
    })();
    if result.is_err() {
        let _ = unlink_at(directory, &temporary, 0);
    }
    result
}

fn read_record_at<T: serde::de::DeserializeOwned>(
    directory: RawFd,
    name: &str,
    uid: libc::uid_t,
) -> io::Result<T> {
    let file = open_private_at(directory, name, false, false, uid)?;
    if file.metadata()?.len() > MAX_RECORD_BYTES {
        return Err(invalid_data("job record exceeds size limit"));
    }
    serde_json::from_reader(file.take(MAX_RECORD_BYTES + 1)).map_err(invalid_json)
}

fn create_private_file_at(directory: RawFd, name: &str, uid: libc::uid_t) -> io::Result<File> {
    let name = c_string(name)?;
    let fd = unsafe {
        libc::openat(
            directory,
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    let file = File::from(cvt_fd(fd)?);
    validate_private_file(&file, uid)?;
    Ok(file)
}

fn open_private_at(
    directory: RawFd,
    name: &str,
    write: bool,
    append: bool,
    uid: libc::uid_t,
) -> io::Result<File> {
    let name = c_string(name)?;
    let access = if write {
        libc::O_WRONLY
    } else {
        libc::O_RDONLY
    };
    let append_flag = if append { libc::O_APPEND } else { 0 };
    let fd = unsafe {
        libc::openat(
            directory,
            name.as_ptr(),
            access | append_flag | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    let file = File::from(cvt_fd(fd)?);
    validate_private_file(&file, uid)?;
    Ok(file)
}

fn validate_private_file(file: &File, uid: libc::uid_t) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "insecure remote job file",
        ));
    }
    Ok(())
}

fn open_directory_path(path: &Path, uid: libc::uid_t, private: bool) -> io::Result<OwnedFd> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| invalid_data("remote job path contains NUL"))?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    let fd = cvt_fd(fd)?;
    validate_directory_fd(fd.as_raw_fd(), uid, private)?;
    Ok(fd)
}

fn ensure_directory_at(
    parent: RawFd,
    name: &str,
    uid: libc::uid_t,
    private: bool,
) -> io::Result<OwnedFd> {
    match mkdir_at(parent, name, 0o700) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    open_directory_at(parent, name, uid, private)
}

fn open_directory_at(
    parent: RawFd,
    name: &str,
    uid: libc::uid_t,
    private: bool,
) -> io::Result<OwnedFd> {
    let name = c_string(name)?;
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    let fd = cvt_fd(fd)?;
    validate_directory_fd(fd.as_raw_fd(), uid, private)?;
    Ok(fd)
}

fn validate_directory_fd(fd: RawFd, uid: libc::uid_t, private: bool) -> io::Result<()> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let stat = unsafe { stat.assume_init() };
    let mode = stat.st_mode as libc::mode_t;
    let wrong_mode = if private {
        mode & 0o777 != 0o700
    } else {
        mode & 0o022 != 0
    };
    if mode & libc::S_IFMT != libc::S_IFDIR || stat.st_uid != uid || wrong_mode {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "insecure remote job directory",
        ));
    }
    Ok(())
}

fn mkdir_at(parent: RawFd, name: &str, mode: libc::mode_t) -> io::Result<()> {
    let name = c_string(name)?;
    if unsafe { libc::mkdirat(parent, name.as_ptr(), mode) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn rename_at(from_dir: RawFd, from: &str, to_dir: RawFd, to: &str) -> io::Result<()> {
    let from = c_string(from)?;
    let to = c_string(to)?;
    if unsafe { libc::renameat(from_dir, from.as_ptr(), to_dir, to.as_ptr()) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn unlink_at(directory: RawFd, name: &str, flags: i32) -> io::Result<()> {
    let name = c_string(name)?;
    if unsafe { libc::unlinkat(directory, name.as_ptr(), flags) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn unlink_at_if_exists(directory: RawFd, name: &str, flags: i32) -> io::Result<()> {
    match unlink_at(directory, name, flags) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn sync_fd(fd: RawFd) -> io::Result<()> {
    if unsafe { libc::fsync(fd) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn cvt_fd(fd: RawFd) -> io::Result<OwnedFd> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn c_string(value: &str) -> io::Result<CString> {
    CString::new(value).map_err(|_| invalid_data("remote job entry contains NUL"))
}

fn checked_id(id: &JobId) -> io::Result<String> {
    JobId::parse(id.as_str())
        .map(|id| id.as_str().to_owned())
        .map_err(|_| invalid_data("invalid job id"))
}

fn directory_names(directory: RawFd) -> io::Result<Vec<String>> {
    let path = format!("/proc/self/fd/{directory}");
    let mut names = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
        let value = name
            .to_str()
            .ok_or_else(|| invalid_data("remote job entry is not UTF-8"))?;
        names.push(value.to_owned());
    }
    Ok(names)
}

fn lock_job(directory: RawFd, uid: libc::uid_t, nonblocking: bool) -> io::Result<File> {
    let file = open_private_at(directory, LOCK_FILE, false, false, uid)?;
    let flags = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
    if unsafe { libc::flock(file.as_raw_fd(), flags) } == 0 {
        Ok(file)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn cleanup_job_files(directory: RawFd) {
    for name in [
        CANCEL_FILE,
        REQUEST_FILE,
        STATE_FILE,
        STDOUT_FILE,
        STDERR_FILE,
        LOCK_FILE,
    ] {
        let _ = unlink_at(directory, name, 0);
    }
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

fn process_matches(expected: &ProcessIdentity) -> bool {
    u32::try_from(expected.pid)
        .ok()
        .and_then(|pid| process_identity(pid).ok())
        .is_some_and(|observed| observed == *expected)
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
