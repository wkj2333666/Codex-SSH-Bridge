use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::error::{BridgeError, BridgeResult};

use super::SshPolicy;

pub fn build_ssh_argv(policy: &SshPolicy, host: &str, remote_command: &str) -> Vec<OsString> {
    let mut argv = policy.options.clone();
    argv.push(OsString::from("--"));
    argv.push(OsString::from(host));
    if !remote_command.is_empty() {
        argv.push(OsString::from(remote_command));
    }
    debug_assert!(argv.iter().any(|argument| argument == OsStr::new("--")));
    argv
}

pub fn build_sshfs_argv(
    policy: &SshPolicy,
    host: &str,
    remote_path: &str,
    mountpoint: &Path,
    allow_nonempty: bool,
) -> BridgeResult<Vec<OsString>> {
    if !remote_path.starts_with('/') || remote_path.as_bytes().contains(&0) {
        return Err(BridgeError::invalid_argument(
            "SSHFS remote path must be absolute and contain no NUL",
        ));
    }
    if !mountpoint.is_absolute() || mountpoint.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(BridgeError::invalid_argument(
            "SSHFS mountpoint must be an absolute local path",
        ));
    }

    let mut argv = Vec::with_capacity(policy.options.len() + 24);
    argv.push(OsString::from(format!("{host}:{remote_path}")));
    argv.push(mountpoint.as_os_str().to_owned());
    push_option(&mut argv, "ssh_command=/usr/bin/ssh");
    argv.extend(policy.options.iter().cloned());
    push_option(&mut argv, "reconnect");
    if allow_nonempty {
        push_option(&mut argv, "nonempty");
    }
    Ok(argv)
}

pub fn validate_sshfs_mountpoint(path: &Path, allow_nonempty: bool) -> BridgeResult<PathBuf> {
    ValidatedMountpoint::open(path, allow_nonempty).map(|validated| validated.path)
}

#[derive(Debug)]
pub(crate) struct ValidatedMountpoint {
    path: PathBuf,
    directory: File,
    device: u64,
    inode: u64,
}

impl ValidatedMountpoint {
    pub(crate) fn open(path: &Path, allow_nonempty: bool) -> BridgeResult<Self> {
        if !path.is_absolute() {
            return Err(BridgeError::invalid_argument(
                "SSHFS mountpoint must be an absolute local path",
            ));
        }
        if path.as_os_str().as_encoded_bytes().contains(&0) {
            return Err(BridgeError::invalid_argument(
                "SSHFS mountpoint must contain no NUL",
            ));
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|error| {
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ELOOP) | Some(libc::ENOTDIR)
                ) {
                    BridgeError::invalid_argument(
                        "SSHFS mountpoint must be a real local directory, not a symlink",
                    )
                } else {
                    BridgeError::io(error)
                }
            })?;
        let opened = directory.metadata().map_err(BridgeError::io)?;
        // SAFETY: geteuid has no preconditions and reads process credentials.
        let uid = unsafe { libc::geteuid() };
        if !opened.is_dir() || opened.uid() != uid {
            return Err(BridgeError::invalid_argument(
                "SSHFS mountpoint must be a directory owned by the current user",
            ));
        }
        let validated = Self {
            path: path.to_owned(),
            device: opened.dev(),
            inode: opened.ino(),
            directory,
        };
        validated.ensure_path_binding()?;
        if !allow_nonempty
            && std::fs::read_dir(validated.fd_path())
                .map_err(BridgeError::io)?
                .next()
                .transpose()
                .map_err(BridgeError::io)?
                .is_some()
        {
            return Err(BridgeError::invalid_argument(
                "SSHFS mountpoint is not empty; pass --allow-nonempty only after inspection",
            ));
        }
        Ok(validated)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn fd_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
    }

    pub(crate) fn ensure_path_binding(&self) -> BridgeResult<()> {
        let current = std::fs::symlink_metadata(&self.path).map_err(BridgeError::io)?;
        if current.file_type().is_symlink()
            || !current.is_dir()
            || current.dev() != self.device
            || current.ino() != self.inode
        {
            return Err(BridgeError::invalid_argument(
                "SSHFS mountpoint path changed after validation",
            ));
        }
        Ok(())
    }

    pub(crate) fn mount_id(&self) -> BridgeResult<u64> {
        let path = PathBuf::from(format!("/proc/self/fdinfo/{}", self.directory.as_raw_fd()));
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(BridgeError::io)?
            .take(16 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(BridgeError::io)?;
        if bytes.len() > 16 * 1024 {
            return Err(BridgeError::io("mountpoint fdinfo exceeded its limit"));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| BridgeError::io("mountpoint fdinfo is not UTF-8"))?;
        text.lines()
            .find_map(|line| line.strip_prefix("mnt_id:"))
            .map(str::trim)
            .ok_or_else(|| BridgeError::io("mountpoint fdinfo has no mount ID"))?
            .parse::<u64>()
            .map_err(|_| BridgeError::io("mountpoint fdinfo mount ID is invalid"))
    }
}

fn push_option(argv: &mut Vec<OsString>, value: impl Into<OsString>) {
    argv.push(OsString::from("-o"));
    argv.push(value.into());
}
