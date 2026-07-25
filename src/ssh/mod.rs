#![allow(
    clippy::result_large_err,
    reason = "Task 1 fixes BridgeResult<T> to an inline BridgeError representation"
)]

mod argv;
mod dispatcher;
mod frame;
mod helper;
mod process;
mod session;

use std::ffi::{CString, OsStr, OsString};
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::config::EffectiveLimits;
use crate::error::{BridgeError, BridgeResult};

pub(crate) use argv::ValidatedMountpoint;
pub use argv::{build_ssh_argv, build_sshfs_argv, validate_sshfs_mountpoint};
pub(crate) use process::{
    FixedOperationKind, FixedRunRequest, FixedRunResult, RootedPathInputs, render_fixed_command,
};
pub use process::{RunRequest, RunResult, RunTiming, SshRunner};
pub(crate) use session::{HostSession, SessionOutput, SessionRequest, SessionResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HelperMode {
    Persistent,
    Temporary,
    Shell,
}

const RUNTIME_DIRECTORY: &str = "codex-ssh-bridge";
const CONTROL_FILENAME_BYTES: usize = 3 + 32;
const UNIX_SOCKET_PATH_MAX_BYTES: usize = 107;
pub(crate) const SERVER_ALIVE_INTERVAL_SECONDS: u64 = 15;
pub(crate) const SERVER_ALIVE_COUNT_MAX: u64 = 3;
const SSH_G_OPTIONS: &[&str] = &[
    "BatchMode=yes",
    "StrictHostKeyChecking=yes",
    "ForwardAgent=no",
    "ForwardX11=no",
    "ClearAllForwardings=yes",
    "PermitLocalCommand=no",
    "RequestTTY=no",
    "ControlPersist=300",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePaths {
    directory: PathBuf,
}

impl RuntimePaths {
    pub fn discover() -> BridgeResult<Self> {
        match std::env::var_os("XDG_RUNTIME_DIR").filter(|value| !value.is_empty()) {
            Some(base) => {
                let base = Path::new(&base);
                let directory = base.join(RUNTIME_DIRECTORY);
                if control_path_candidate_is_usable(&directory) {
                    match Self::ensure_from_base(base) {
                        Ok(paths) if paths.is_writable() => Ok(paths),
                        Ok(_) => Self::ensure_tmp_fallback(),
                        Err(error) if error.code == crate::ErrorCode::Io => {
                            Self::ensure_tmp_fallback()
                        }
                        Err(error) => Err(error),
                    }
                } else {
                    Self::ensure_tmp_fallback()
                }
            }
            None => Self::ensure_tmp_fallback(),
        }
    }

    pub fn ensure_from_base(base: &Path) -> BridgeResult<Self> {
        validate_openssh_config_path(&base.join(RUNTIME_DIRECTORY))?;
        Self::ensure_in_base(base, OsStr::new(RUNTIME_DIRECTORY), true)
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    fn is_writable(&self) -> bool {
        tempfile::Builder::new()
            .prefix(".codex-ssh-bridge-writable-")
            .tempdir_in(&self.directory)
            .is_ok()
    }

    fn ensure_tmp_fallback() -> BridgeResult<Self> {
        // SAFETY: geteuid has no preconditions and only reads process credentials.
        let uid = unsafe { libc::geteuid() };
        let leaf = OsString::from(format!("{RUNTIME_DIRECTORY}-{uid}"));
        Self::ensure_in_base(Path::new("/tmp"), &leaf, false)
    }

    fn ensure_in_base(
        base: &Path,
        leaf: &OsStr,
        require_current_user_base: bool,
    ) -> BridgeResult<Self> {
        let base_directory = open_secure_absolute_directory(base, require_current_user_base)?;
        let leaf_name = path_component(leaf)?;
        // SAFETY: base_directory is an open directory and leaf_name is a live
        // NUL-terminated component. mkdirat does not retain either pointer.
        let created =
            unsafe { libc::mkdirat(base_directory.as_raw_fd(), leaf_name.as_ptr(), 0o700) };
        if created != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                return Err(BridgeError::io(error));
            }
        }

        let directory = base.join(leaf);
        let runtime_directory = openat_directory(&base_directory, leaf, &directory)?;
        let metadata = runtime_directory.metadata().map_err(BridgeError::io)?;
        // SAFETY: geteuid has no preconditions and only reads process credentials.
        let uid = unsafe { libc::geteuid() };
        if !metadata.is_dir() || metadata.uid() != uid {
            return Err(unsafe_runtime_path(
                &directory,
                "runtime path must be a directory owned by the current user",
            ));
        }
        if metadata.mode() & 0o7777 != 0o700 {
            return Err(unsafe_runtime_path(
                &directory,
                "runtime directory permissions must be 0700",
            ));
        }

        Ok(Self { directory })
    }
}

fn open_secure_absolute_directory(
    path: &Path,
    require_current_user_base: bool,
) -> BridgeResult<File> {
    if !path.is_absolute() {
        return Err(unsafe_runtime_path(path, "runtime base must be absolute"));
    }

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut directory = options.open("/").map_err(BridgeError::io)?;
    let root_metadata = directory.metadata().map_err(BridgeError::io)?;
    let trusted_system_uid = root_metadata.uid();
    // SAFETY: geteuid has no preconditions and only reads process credentials.
    let current_uid = unsafe { libc::geteuid() };
    validate_ancestor(
        Path::new("/"),
        &root_metadata,
        trusted_system_uid,
        current_uid,
    )?;

    let mut resolved = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                resolved.push(name);
                directory = openat_directory(&directory, name, &resolved)?;
                validate_ancestor(
                    &resolved,
                    &directory.metadata().map_err(BridgeError::io)?,
                    trusted_system_uid,
                    current_uid,
                )?;
            }
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(unsafe_runtime_path(
                    path,
                    "runtime base must be a normalized absolute path",
                ));
            }
        }
    }

    if require_current_user_base {
        let metadata = directory.metadata().map_err(BridgeError::io)?;
        if metadata.uid() != current_uid {
            return Err(unsafe_runtime_path(
                path,
                "runtime base must be owned by the current user",
            ));
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(unsafe_runtime_path(
                path,
                "runtime base must not be writable by group or other users",
            ));
        }
    }

    Ok(directory)
}

fn openat_directory(parent: &File, name: &OsStr, path: &Path) -> BridgeResult<File> {
    let name = path_component(name)?;
    // SAFETY: parent is an open directory and name is a live NUL-terminated
    // component. openat does not retain the pointer. A successful fd is owned
    // immediately by File below.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ELOOP | libc::ENOTDIR) => Err(unsafe_runtime_path(
                path,
                "runtime path components must be real directories",
            )),
            _ => Err(BridgeError::io(error)),
        };
    }
    // SAFETY: descriptor was returned uniquely owned by openat above.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn validate_ancestor(
    path: &Path,
    metadata: &std::fs::Metadata,
    trusted_system_uid: u32,
    current_uid: u32,
) -> BridgeResult<()> {
    if !metadata.is_dir() {
        return Err(unsafe_runtime_path(
            path,
            "runtime ancestors must be directories",
        ));
    }
    if metadata.uid() != trusted_system_uid && metadata.uid() != current_uid {
        return Err(unsafe_runtime_path(
            path,
            "runtime ancestors must be owned by root or the current user",
        ));
    }
    if metadata.mode() & 0o022 != 0
        && !(path == Path::new("/tmp")
            && metadata.uid() == trusted_system_uid
            && metadata.mode() & 0o1000 != 0)
    {
        return Err(unsafe_runtime_path(
            path,
            "runtime ancestors must not be writable by group or other users",
        ));
    }
    Ok(())
}

fn path_component(value: &OsStr) -> BridgeResult<CString> {
    if value.is_empty() || value.as_bytes().contains(&b'/') {
        return Err(unsafe_runtime_directory("invalid runtime path component"));
    }
    CString::new(value.as_bytes())
        .map_err(|_| unsafe_runtime_directory("runtime paths cannot contain NUL"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPolicy {
    options: Vec<OsString>,
    control_path: PathBuf,
}

impl SshPolicy {
    pub fn for_host(
        alias: &str,
        limits: EffectiveLimits,
        runtime_paths: &RuntimePaths,
        resolved_connection_identity: &str,
    ) -> BridgeResult<Self> {
        let control_path = runtime_paths
            .directory
            .join(control_filename(alias, resolved_connection_identity));
        let control_option = encoded_control_path_option(&control_path)?;

        let mut options = Vec::new();
        for option in [
            "BatchMode=yes",
            "StrictHostKeyChecking=yes",
            "ForwardAgent=no",
            "ForwardX11=no",
            "ClearAllForwardings=yes",
            "PermitLocalCommand=no",
            "RequestTTY=no",
            "ControlMaster=auto",
            "ControlPersist=300",
        ] {
            options.push(OsString::from("-o"));
            options.push(OsString::from(option));
        }
        for option in server_alive_options() {
            options.push(OsString::from("-o"));
            options.push(option);
        }
        options.push(OsString::from("-o"));
        options.push(openssh_connect_timeout_option(limits.connect_timeout_ms));
        options.push(OsString::from("-o"));
        options.push(control_option);

        Ok(Self {
            options,
            control_path,
        })
    }

    pub fn control_path(&self) -> &Path {
        &self.control_path
    }
}

pub(crate) fn server_alive_options() -> [OsString; 2] {
    [
        OsString::from(format!(
            "ServerAliveInterval={SERVER_ALIVE_INTERVAL_SECONDS}"
        )),
        OsString::from(format!("ServerAliveCountMax={SERVER_ALIVE_COUNT_MAX}")),
    ]
}

pub(crate) fn build_ssh_g_argv(host: &str, connect_timeout_ms: u64) -> Vec<OsString> {
    let mut argv = vec![OsString::from("-G")];
    for option in SSH_G_OPTIONS {
        argv.push(OsString::from("-o"));
        argv.push(OsString::from(option));
    }
    for option in server_alive_options() {
        argv.push(OsString::from("-o"));
        argv.push(option);
    }
    argv.push(OsString::from("-o"));
    argv.push(openssh_connect_timeout_option(connect_timeout_ms));
    argv.push(OsString::from("--"));
    argv.push(OsString::from(host));
    argv
}

fn openssh_connect_timeout_option(milliseconds: u64) -> OsString {
    let seconds = milliseconds.div_ceil(1_000).max(1);
    OsString::from(format!("ConnectTimeout={seconds}"))
}

fn control_path_candidate_is_usable(directory: &Path) -> bool {
    let control_path = directory.join("x".repeat(CONTROL_FILENAME_BYTES));
    control_path.as_os_str().as_bytes().len() <= UNIX_SOCKET_PATH_MAX_BYTES
        && validate_openssh_config_path(&control_path).is_ok()
}

fn validate_openssh_config_path(path: &Path) -> BridgeResult<&str> {
    let value = path
        .to_str()
        .ok_or_else(|| unsafe_runtime_path(path, "ControlPath must be valid UTF-8 for OpenSSH"))?;
    if value.contains(['\n', '\r']) {
        return Err(unsafe_runtime_path(
            path,
            "ControlPath cannot contain carriage returns or newlines",
        ));
    }
    Ok(value)
}

fn encoded_control_path_option(control_path: &Path) -> BridgeResult<OsString> {
    if control_path.as_os_str().as_bytes().len() > UNIX_SOCKET_PATH_MAX_BYTES {
        return Err(BridgeError::invalid_config(
            "ControlPath exceeds the Unix socket path limit",
        ));
    }
    let value = validate_openssh_config_path(control_path)?;
    let mut encoded = String::from("ControlPath=\"");
    for character in value.chars() {
        match character {
            '"' => encoded.push_str("\\\""),
            '\\' => encoded.push_str("\\\\"),
            '%' => encoded.push_str("%%"),
            _ => encoded.push(character),
        }
    }
    encoded.push('"');
    Ok(OsString::from(encoded))
}

fn control_filename(alias: &str, resolved_connection_identity: &str) -> String {
    let mut digest = Sha256::new();
    digest.update((alias.len() as u64).to_be_bytes());
    digest.update(alias.as_bytes());
    digest.update((resolved_connection_identity.len() as u64).to_be_bytes());
    digest.update(resolved_connection_identity.as_bytes());
    let digest = digest.finalize();
    let mut filename = String::from("cm-");
    for byte in &digest[..16] {
        write!(&mut filename, "{byte:02x}").expect("writing to a String cannot fail");
    }
    filename
}

fn unsafe_runtime_directory(message: &str) -> BridgeError {
    BridgeError::invalid_config(message)
}

fn unsafe_runtime_path(path: &Path, message: &str) -> BridgeError {
    let mut error = unsafe_runtime_directory(message);
    error.details.path = Some(path.to_string_lossy().into_owned());
    error
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::TempDir;

    use super::RuntimePaths;

    #[test]
    fn writable_probe_rejects_read_only_runtime_directory() {
        let directory = TempDir::new().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let paths = RuntimePaths {
            directory: directory.path().to_owned(),
        };
        assert!(!paths.is_writable());
    }
}
