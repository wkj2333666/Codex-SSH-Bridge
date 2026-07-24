use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::capability::Capability;
use crate::error::{BridgeError, BridgeResult, ErrorCode};
use crate::quote::shell_word;

const HELPER_DIRECTORY_ENV: &str = "CODEX_SSH_BRIDGE_HELPERS_DIR";
const HELPER_DIRECTORY_NAME: &str = "remote-helpers";
const HELPER_BOOTSTRAP_TAG: &str = "codex-ssh-helper-bootstrap-1";
const PERSISTENT_HELPER_BOOTSTRAP_TAG: &str = "codex-ssh-persistent-helper-bootstrap-1";
const MAX_HELPER_BYTES: u64 = 256 * 1024 * 1024;
pub(crate) const BRIDGE_VERSION: &str = env!("CARGO_PKG_VERSION");

const HELPER_BOOTSTRAP_SCRIPT: &str = r#"set -u
umask 077
bootstrap_tag=${1-}
helper_length=${2-}
max_frame=${3-}
[ "$bootstrap_tag" = codex-ssh-helper-bootstrap-1 ] || exit 64
case "$helper_length:$max_frame" in
    ''|*[!0-9:]*|*:*:) exit 64 ;;
esac
[ "$helper_length" -gt 0 ] || exit 64
[ "$max_frame" -gt 0 ] || exit 64
base=${TMPDIR:-/tmp}/codex-ssh-bridge-helper.$$
suffix=0
while ! (umask 077 && mkdir "$base" 2>/dev/null); do
    suffix=$((suffix + 1))
    [ "$suffix" -le 100 ] || exit 73
    base=${TMPDIR:-/tmp}/codex-ssh-bridge-helper.$$.$suffix
done
helper=$base/helper
cleanup() { rm -rf -- "$base"; }
trap cleanup EXIT HUP INT TERM
: >"$helper" || exit 74
read_bytes=0
while [ "$read_bytes" -lt "$helper_length" ]; do
    chunk=$((helper_length - read_bytes))
    [ "$chunk" -le 65536 ] || chunk=65536
    dd bs="$chunk" count=1 >>"$helper" 2>/dev/null || exit 74
    now=$(wc -c <"$helper" | tr -d '[:space:]') || exit 74
    case "$now" in ''|*[!0-9]*) exit 74 ;; esac
    [ "$now" -gt "$read_bytes" ] || exit 74
    [ "$now" -le "$helper_length" ] || exit 74
    read_bytes=$now
done
[ "$read_bytes" -eq "$helper_length" ] || exit 74
chmod 700 "$helper" || exit 74
CODEX_SSH_HELPER_PATH="$helper" exec "$helper" --max-frame "$max_frame"
"#;

const PERSISTENT_HELPER_BOOTSTRAP_SCRIPT: &str = r#"set -u
umask 077
bootstrap_tag=${1-}
max_frame=${2-}
bridge_version=${3-}
helper_target=${4-}
helper_arch=${5-}
helper_length=${6-}
helper_sha256=${7-}
[ "$bootstrap_tag" = codex-ssh-persistent-helper-bootstrap-1 ] || exit 64
case "$max_frame:$helper_length" in
    ''|*[!0-9:]*|*:*:) exit 64 ;;
esac
[ "$max_frame" -gt 0 ] || exit 64
[ "$helper_length" -gt 0 ] || exit 64
case "$bridge_version:$helper_target:$helper_arch" in
    ''|*[!A-Za-z0-9._:-]*) exit 64 ;;
esac
case "$helper_sha256" in
    ''|*[!0-9a-f]*) exit 64 ;;
esac
[ "${#helper_sha256}" -eq 64 ] || exit 64
home=$(CDPATH= cd -P -- ~ 2>/dev/null && pwd -P) || exit 74
case "$home" in /*) ;; *) exit 74 ;; esac
root=$home/.local
data_root=$root/share
bridge_root=$data_root/codex-ssh-bridge
helpers_root=$bridge_root/helpers
version_root=$helpers_root/$bridge_version
target_root=$version_root/$helper_target
helper=$target_root/helper
lock=$target_root/.install.lock
record_status() {
    if [ -n "${FAKE_SSH_INSTALL_LOG-}" ]; then
        printf '%s\n' "$1" >>"$FAKE_SSH_INSTALL_LOG"
    fi
}
record_bytes() {
    if [ -n "${FAKE_SSH_HELPER_BYTES_LOG-}" ]; then
        printf '%s\n' "$1" >>"$FAKE_SSH_HELPER_BYTES_LOG"
    fi
}
mkdir -p "$target_root" 2>/dev/null || exit 74
for directory in "$root" "$data_root" "$bridge_root" "$helpers_root" "$version_root" "$target_root"; do
    [ -d "$directory" ] || exit 74
    [ ! -L "$directory" ] || exit 74
    chmod 700 "$directory" || exit 74
done
valid_helper() {
    [ -f "$helper" ] && [ ! -L "$helper" ] && [ -x "$helper" ] || return 1
    mode=$(stat -c '%a' "$helper" 2>/dev/null || stat -f '%Lp' "$helper" 2>/dev/null) || return 1
    [ "$mode" = 700 ] || return 1
    size=$(wc -c <"$helper" | tr -d '[:space:]') || return 1
    [ "$size" = "$helper_length" ] || return 1
    digest=$(sha256sum "$helper" 2>/dev/null) || return 1
    digest=${digest%% *}
    [ "$digest" = "$helper_sha256" ]
}
lock_owned=0
cleanup() {
    if [ "$lock_owned" -eq 1 ]; then
        rm -f -- "$lock/pid" 2>/dev/null || true
        rmdir "$lock" 2>/dev/null || true
    fi
    rm -f "$target_root/.helper.$$.$helper_length.tmp" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM
stale_lock() {
    owner=$(cat "$lock/pid" 2>/dev/null || true)
    case "$owner" in
        ''|*[!0-9]*) return 1 ;;
    esac
    kill -0 "$owner" 2>/dev/null && return 1
    rm -f -- "$lock/pid" 2>/dev/null || return 1
    rmdir "$lock" 2>/dev/null
}
wait_count=0
while ! mkdir "$lock" 2>/dev/null; do
    if valid_helper; then
        record_bytes 0
        record_status HIT
        printf '%s\n' 'CXSB-INSTALL-1 HIT'
        exec "$helper" --max-frame "$max_frame"
    fi
    if stale_lock; then
        continue
    fi
    wait_count=$((wait_count + 1))
    [ "$wait_count" -lt 30 ] || exit 73
    sleep 1
done
lock_owned=1
printf '%s\n' "$$" >"$lock/pid" || exit 74
if valid_helper; then
    rm -f -- "$lock/pid" 2>/dev/null || exit 74
    rmdir "$lock" 2>/dev/null || exit 74
    lock_owned=0
    record_bytes 0
    record_status HIT
    printf '%s\n' 'CXSB-INSTALL-1 HIT'
    exec "$helper" --max-frame "$max_frame"
fi
record_status NEED
printf '%s\n' 'CXSB-INSTALL-1 NEED'
temporary=$target_root/.helper.$$.$helper_length.tmp
: >"$temporary" || exit 74
read_bytes=0
while [ "$read_bytes" -lt "$helper_length" ]; do
    chunk=$((helper_length - read_bytes))
    [ "$chunk" -le 65536 ] || chunk=65536
    dd bs="$chunk" count=1 >>"$temporary" 2>/dev/null || exit 74
    now=$(wc -c <"$temporary" | tr -d '[:space:]') || exit 74
    case "$now" in ''|*[!0-9]*) exit 74 ;; esac
    [ "$now" -gt "$read_bytes" ] || exit 74
    [ "$now" -le "$helper_length" ] || exit 74
    read_bytes=$now
done
[ "$read_bytes" -eq "$helper_length" ] || exit 74
record_bytes "$read_bytes"
digest=$(sha256sum "$temporary" 2>/dev/null) || exit 74
digest=${digest%% *}
[ "$digest" = "$helper_sha256" ] || exit 74
chmod 700 "$temporary" || exit 74
mv -f "$temporary" "$helper" || exit 74
rm -f -- "$lock/pid" 2>/dev/null || exit 74
rmdir "$lock" 2>/dev/null || exit 74
lock_owned=0
exec "$helper" --max-frame "$max_frame"
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HelperArtifact {
    pub(crate) path: PathBuf,
    pub(crate) target: &'static str,
    pub(crate) arch: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HelperIdentity {
    pub(crate) version: String,
    pub(crate) target: &'static str,
    pub(crate) arch: &'static str,
    pub(crate) length: usize,
    pub(crate) sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootstrapStatus {
    Hit,
    Need,
}

pub(crate) fn helper_identity(
    artifact: &HelperArtifact,
    bytes: &[u8],
) -> BridgeResult<HelperIdentity> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_HELPER_BYTES {
        return Err(BridgeError::invalid_config(
            "remote helper artifact size is outside the safe bound",
        ));
    }
    Ok(HelperIdentity {
        version: BRIDGE_VERSION.to_owned(),
        target: artifact.target,
        arch: artifact.arch,
        length: bytes.len(),
        sha256: sha256_hex(bytes),
    })
}

pub(crate) fn parse_bootstrap_status(bytes: &[u8]) -> BridgeResult<BootstrapStatus> {
    if bytes.len() > 64 || bytes.contains(&0) {
        return Err(BridgeError::new(
            ErrorCode::ProtocolError,
            "persistent helper bootstrap status is invalid",
            false,
        ));
    }
    match bytes {
        b"CXSB-INSTALL-1 HIT\n" => Ok(BootstrapStatus::Hit),
        b"CXSB-INSTALL-1 NEED\n" => Ok(BootstrapStatus::Need),
        _ => Err(BridgeError::new(
            ErrorCode::ProtocolError,
            "persistent helper bootstrap status is invalid",
            false,
        )),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

pub(crate) fn helper_artifact(capability: &Capability) -> Option<HelperArtifact> {
    if capability.kernel_name.as_deref() != Some("Linux") {
        return None;
    }
    let (target, arch) = helper_target_for_arch(capability.machine_arch.as_deref()?)?;
    let directory = helper_directory().ok()?;
    let path = directory.join(target);
    validate_artifact_path(&directory, &path).ok()?;
    Some(HelperArtifact { path, target, arch })
}

fn helper_target_for_arch(machine_arch: &str) -> Option<(&'static str, &'static str)> {
    match machine_arch {
        "x86_64" => Some(("x86_64-unknown-linux-musl", "x86_64")),
        "aarch64" => Some(("aarch64-unknown-linux-musl", "aarch64")),
        "armv7l" | "armv7" => Some(("armv7-unknown-linux-musleabihf", "armv7l")),
        "riscv64" => Some(("riscv64gc-unknown-linux-gnu", "riscv64")),
        "ppc64le" => Some(("powerpc64le-unknown-linux-gnu", "ppc64le")),
        "s390x" => Some(("s390x-unknown-linux-gnu", "s390x")),
        _ => None,
    }
}

pub(crate) fn helper_bytes(artifact: &HelperArtifact) -> BridgeResult<Vec<u8>> {
    let directory = artifact
        .path
        .parent()
        .ok_or_else(|| BridgeError::invalid_config("remote helper artifact has no parent"))?;
    validate_artifact_path(directory, &artifact.path)?;
    let metadata = fs::symlink_metadata(&artifact.path).map_err(BridgeError::io)?;
    if metadata.len() == 0 || metadata.len() > MAX_HELPER_BYTES {
        return Err(BridgeError::invalid_config(
            "remote helper artifact size is outside the safe bound",
        ));
    }
    fs::read(&artifact.path).map_err(BridgeError::io)
}

pub(crate) fn helper_command(max_frame_bytes: usize, helper_length: usize) -> BridgeResult<String> {
    if max_frame_bytes == 0 || helper_length == 0 {
        return Err(BridgeError::invalid_argument(
            "remote helper bootstrap lengths must be positive",
        ));
    }
    let script = shell_word(HELPER_BOOTSTRAP_SCRIPT)?;
    let tag = shell_word(HELPER_BOOTSTRAP_TAG)?;
    let length = shell_word(&helper_length.to_string())?;
    let max_frame = shell_word(&max_frame_bytes.to_string())?;
    Ok(format!("sh -c {script} -- {tag} {length} {max_frame}"))
}

pub(crate) fn persistent_helper_command(
    max_frame_bytes: usize,
    identity: &HelperIdentity,
) -> BridgeResult<String> {
    if max_frame_bytes == 0 || identity.length == 0 || identity.sha256.len() != 64 {
        return Err(BridgeError::invalid_argument(
            "persistent helper bootstrap arguments are invalid",
        ));
    }
    let script = shell_word(PERSISTENT_HELPER_BOOTSTRAP_SCRIPT)?;
    let tag = shell_word(PERSISTENT_HELPER_BOOTSTRAP_TAG)?;
    let max_frame = shell_word(&max_frame_bytes.to_string())?;
    let version = shell_word(&identity.version)?;
    let target = shell_word(identity.target)?;
    let arch = shell_word(identity.arch)?;
    let length = shell_word(&identity.length.to_string())?;
    let sha256 = shell_word(&identity.sha256)?;
    Ok(format!(
        "sh -c {script} -- {tag} {max_frame} {version} {target} {arch} {length} {sha256}"
    ))
}

pub(crate) fn helper_directory() -> BridgeResult<PathBuf> {
    let directory = match std::env::var_os(HELPER_DIRECTORY_ENV) {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => helper_directory_from_executable(
            &std::env::current_exe().map_err(BridgeError::io)?,
        )?,
    };
    Ok(directory)
}

fn helper_directory_from_executable(executable: &Path) -> BridgeResult<PathBuf> {
    let executable = fs::canonicalize(executable).map_err(BridgeError::io)?;
    executable
        .parent()
        .map(|parent| parent.join(HELPER_DIRECTORY_NAME))
        .ok_or_else(|| BridgeError::invalid_config("bridge executable has no parent directory"))
}

fn validate_artifact_path(directory: &Path, path: &Path) -> BridgeResult<()> {
    let directory_metadata = fs::symlink_metadata(directory).map_err(BridgeError::io)?;
    let file_metadata = fs::symlink_metadata(path).map_err(BridgeError::io)?;
    let uid = unsafe { libc::geteuid() };
    if !directory_metadata.is_dir()
        || directory_metadata.file_type().is_symlink()
        || directory_metadata.permissions().mode() & 0o022 != 0
        || (directory_metadata.uid() != uid && directory_metadata.uid() != 0)
        || !file_metadata.is_file()
        || file_metadata.file_type().is_symlink()
        || file_metadata.permissions().mode() & 0o111 == 0
        || file_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(BridgeError::invalid_config(
            "remote helper artifact path is not a private executable",
        ));
    }
    if file_metadata.uid() != uid && file_metadata.uid() != 0 {
        return Err(BridgeError::invalid_config(
            "remote helper artifact has an unexpected owner",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        BootstrapStatus, HelperArtifact, HelperIdentity, helper_artifact, helper_command,
        helper_directory_from_executable, helper_identity, helper_target_for_arch,
        parse_bootstrap_status, persistent_helper_command,
    };
    use crate::capability::{Capability, ShellKind};
    use std::collections::BTreeMap;
    use std::os::unix::fs::symlink;

    fn capability(kernel_name: Option<&str>, machine_arch: Option<&str>) -> Capability {
        Capability {
            physical_root: "/".to_owned(),
            root_device: 1,
            root_inode: 1,
            kernel_name: kernel_name.map(str::to_owned),
            machine_arch: machine_arch.map(str::to_owned),
            shell: ShellKind::PosixSh,
            bash_version: None,
            login_shell: Some("/bin/sh".to_owned()),
            tools: BTreeMap::new(),
        }
    }

    #[test]
    fn supported_architectures_map_to_helper_targets() {
        for (arch, target) in [
            ("x86_64", "x86_64-unknown-linux-musl"),
            ("aarch64", "aarch64-unknown-linux-musl"),
            ("armv7l", "armv7-unknown-linux-musleabihf"),
            ("armv7", "armv7-unknown-linux-musleabihf"),
            ("riscv64", "riscv64gc-unknown-linux-gnu"),
            ("ppc64le", "powerpc64le-unknown-linux-gnu"),
            ("s390x", "s390x-unknown-linux-gnu"),
        ] {
            assert_eq!(
                helper_target_for_arch(arch).map(|(target, _)| target),
                Some(target)
            );
            let capability = capability(Some("Linux"), Some(arch));
            let artifact = helper_artifact(&capability);
            if std::env::var_os("CODEX_SSH_BRIDGE_HELPERS_DIR").is_some() {
                assert_eq!(artifact.map(|artifact| artifact.target), Some(target));
            } else {
                assert!(artifact.is_none());
            }
        }
        assert!(helper_artifact(&capability(Some("Darwin"), Some("x86_64"))).is_none());
        assert!(helper_artifact(&capability(Some("Linux"), Some("mips64"))).is_none());
    }

    #[test]
    fn helper_directory_resolves_the_real_executable_behind_a_stable_symlink() {
        let temporary = tempfile::tempdir().unwrap();
        let versioned_bin = temporary
            .path()
            .join("releases/0.2.7/bin/codex-ssh-bridge");
        std::fs::create_dir_all(versioned_bin.parent().unwrap()).unwrap();
        std::fs::write(&versioned_bin, b"bridge").unwrap();
        let stable_bin = temporary.path().join("bin/codex-ssh-bridge");
        std::fs::create_dir_all(stable_bin.parent().unwrap()).unwrap();
        symlink(&versioned_bin, &stable_bin).unwrap();

        let helper_directory = helper_directory_from_executable(&stable_bin).unwrap();

        assert_eq!(
            helper_directory,
            versioned_bin.parent().unwrap().join(HELPER_DIRECTORY_NAME)
        );
    }

    #[test]
    fn bootstrap_is_shell_quoted_and_carries_exact_lengths() {
        let command = helper_command(8 * 1024 * 1024, 1234).unwrap();
        assert!(command.starts_with("sh -c "));
        assert!(command.contains("codex-ssh-helper-bootstrap-1"));
        assert!(command.contains("1234"));
        assert!(command.contains("8388608"));
        assert!(!command.as_bytes().contains(&0));
    }

    #[test]
    fn bootstrap_uploads_and_executes_the_helper_without_interpreting_bytes() {
        use std::io::{BufReader, Write};
        use std::process::{Command, Stdio};

        let helper_path = std::env::var("CARGO_BIN_EXE_codex-ssh-bridge-helper")
            .or_else(|_| std::env::var("CARGO_BIN_EXE_codex_ssh_bridge_helper"))
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("target/debug/codex-ssh-bridge-helper")
            });
        if !helper_path.is_file() {
            return;
        }
        let bytes = std::fs::read(helper_path).unwrap();
        let command = helper_command(64 * 1024, bytes.len()).unwrap();
        let mut child = Command::new("/bin/sh")
            .args(["-c", &command])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        input.write_all(&bytes).unwrap();
        input.flush().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let hello = crate::remote_helper_protocol::read_frame(&mut output, 64 * 1024)
            .unwrap()
            .unwrap();
        assert_eq!(
            hello.kind,
            crate::remote_helper_protocol::FrameKind::HelloAck
        );
        crate::remote_helper_protocol::write_frame(
            &mut input,
            &crate::remote_helper_protocol::Frame {
                kind: crate::remote_helper_protocol::FrameKind::Close,
                request_id: 0,
                payload: Vec::new(),
            },
            64 * 1024,
        )
        .unwrap();
        input.flush().unwrap();
        drop(input);
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn helper_identity_uses_exact_length_and_sha256() {
        let artifact = HelperArtifact {
            path: std::path::PathBuf::from("/tmp/helper"),
            target: "x86_64-unknown-linux-musl",
            arch: "x86_64",
        };
        let identity = helper_identity(&artifact, b"abc").unwrap();
        assert_eq!(identity.length, 3);
        assert_eq!(identity.target, "x86_64-unknown-linux-musl");
        assert_eq!(identity.arch, "x86_64");
        assert_eq!(
            identity.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn bootstrap_status_accepts_only_hit_or_need() {
        assert_eq!(
            parse_bootstrap_status(b"CXSB-INSTALL-1 HIT\n").unwrap(),
            BootstrapStatus::Hit
        );
        assert_eq!(
            parse_bootstrap_status(b"CXSB-INSTALL-1 NEED\n").unwrap(),
            BootstrapStatus::Need
        );
    }

    #[test]
    fn bootstrap_status_rejects_trailing_or_unbounded_data() {
        for value in [
            b"CXSB-INSTALL-1 HIT".as_slice(),
            b"CXSB-INSTALL-1 HIT\nextra".as_slice(),
            b"CXSB-INSTALL-1 NOPE\n".as_slice(),
            b"CXSB-INSTALL-1 HIT\0\n".as_slice(),
        ] {
            let error = parse_bootstrap_status(value).unwrap_err();
            assert_eq!(error.code, crate::error::ErrorCode::ProtocolError);
        }
        let oversized = [b'X'; 65];
        let error = parse_bootstrap_status(&oversized).unwrap_err();
        assert_eq!(error.code, crate::error::ErrorCode::ProtocolError);
    }

    fn helper_fixture() -> (std::path::PathBuf, Vec<u8>) {
        let helper_path = std::env::var("CARGO_BIN_EXE_codex-ssh-bridge-helper")
            .or_else(|_| std::env::var("CARGO_BIN_EXE_codex_ssh_bridge_helper"))
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("target/debug/codex-ssh-bridge-helper")
            });
        if !helper_path.is_file() {
            panic!("helper fixture is unavailable: {}", helper_path.display());
        }
        let bytes = std::fs::read(&helper_path).unwrap();
        (helper_path, bytes)
    }

    fn persistent_identity(bytes: &[u8]) -> HelperIdentity {
        let artifact = HelperArtifact {
            path: std::path::PathBuf::from("/tmp/helper"),
            target: "x86_64-unknown-linux-musl",
            arch: "x86_64",
        };
        helper_identity(&artifact, bytes).unwrap()
    }

    #[test]
    fn persistent_bootstrap_contains_no_helper_bytes() {
        let identity = persistent_identity(b"binary\0payload\xff");
        let command = persistent_helper_command(64 * 1024, &identity).unwrap();
        assert!(command.contains("codex-ssh-persistent-helper-bootstrap-1"));
        assert!(command.contains(&identity.version));
        assert!(command.contains(identity.target));
        assert!(command.contains(&identity.sha256));
        assert!(!command.contains("binary"));
        assert!(!command.as_bytes().contains(&0));
    }

    #[test]
    fn persistent_bootstrap_reclaims_dead_lock_owner() {
        use std::io::{BufRead, BufReader, Write};
        use std::process::{Command, Stdio};
        use tempfile::TempDir;

        let home = TempDir::new().unwrap();
        let identity = persistent_identity(b"abc");
        let target = home
            .path()
            .join(".local/share/codex-ssh-bridge/helpers")
            .join(&identity.version)
            .join(identity.target);
        std::fs::create_dir_all(&target).unwrap();
        let lock = target.join(".install.lock");
        std::fs::create_dir(&lock).unwrap();
        std::fs::write(lock.join("pid"), b"99999999\n").unwrap();

        let command = persistent_helper_command(64 * 1024, &identity).unwrap();
        let mut child = Command::new("/bin/sh")
            .args(["-c", &command])
            .env("HOME", home.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut status = String::new();
        output.read_line(&mut status).unwrap();
        assert_eq!(status, "CXSB-INSTALL-1 NEED\n");
        input.write_all(b"abc").unwrap();
        input.flush().unwrap();
        drop(input);
        assert!(!child.wait().unwrap().success());
        assert_eq!(std::fs::read(target.join("helper")).unwrap(), b"abc");
        assert!(!lock.exists());
    }

    #[test]
    fn persistent_bootstrap_rejects_symlink_target_directory() {
        use std::process::{Command, Stdio};
        use tempfile::TempDir;

        let home = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let identity = persistent_identity(b"abc");
        let target_parent = home
            .path()
            .join(".local/share/codex-ssh-bridge/helpers")
            .join(&identity.version);
        std::fs::create_dir_all(&target_parent).unwrap();
        let target = target_parent.join(identity.target);
        std::os::unix::fs::symlink(outside.path(), &target).unwrap();

        let command = persistent_helper_command(64 * 1024, &identity).unwrap();
        let child = Command::new("/bin/sh")
            .args(["-c", &command])
            .env("HOME", home.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        assert!(!child.wait_with_output().unwrap().status.success());
        assert!(!outside.path().join("helper").exists());
    }

    #[test]
    fn persistent_bootstrap_short_upload_preserves_previous_helper() {
        use std::io::{BufRead, BufReader, Write};
        use std::process::{Command, Stdio};
        use tempfile::TempDir;

        let home = TempDir::new().unwrap();
        let identity = persistent_identity(b"new-helper");
        let target = home
            .path()
            .join(".local/share/codex-ssh-bridge/helpers")
            .join(&identity.version)
            .join(identity.target);
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("helper"), b"previous-helper").unwrap();
        std::fs::set_permissions(
            target.join("helper"),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();

        let command = persistent_helper_command(64 * 1024, &identity).unwrap();
        let mut child = Command::new("/bin/sh")
            .args(["-c", &command])
            .env("HOME", home.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut status = String::new();
        output.read_line(&mut status).unwrap();
        assert_eq!(status, "CXSB-INSTALL-1 NEED\n");
        input.write_all(b"new").unwrap();
        input.flush().unwrap();
        drop(input);
        assert!(!child.wait().unwrap().success());
        assert_eq!(
            std::fs::read(target.join("helper")).unwrap(),
            b"previous-helper"
        );
        assert!(!target.join(".install.lock").exists());
    }

    #[test]
    fn persistent_bootstrap_round_trips_hit_without_upload() {
        use std::io::{BufRead, BufReader, Write};
        use std::process::{Command, Stdio};
        use tempfile::TempDir;

        let (_helper_path, bytes) = helper_fixture();
        let identity = persistent_identity(&bytes);
        let home = TempDir::new().unwrap();
        let target = home
            .path()
            .join(".local/share/codex-ssh-bridge/helpers")
            .join(&identity.version)
            .join(identity.target);
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("helper"), &bytes).unwrap();
        std::fs::set_permissions(
            target.join("helper"),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();

        let command = persistent_helper_command(64 * 1024, &identity).unwrap();
        let mut child = Command::new("/bin/sh")
            .args(["-c", &command])
            .env("HOME", home.path())
            .env("TMPDIR", home.path().join("tmp"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        std::fs::create_dir_all(home.path().join("tmp")).unwrap();
        let mut input = child.stdin.take().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut status = String::new();
        output.read_line(&mut status).unwrap();
        assert_eq!(status, "CXSB-INSTALL-1 HIT\n");
        let hello = crate::remote_helper_protocol::read_frame(&mut output, 64 * 1024)
            .unwrap()
            .unwrap();
        assert_eq!(
            hello.kind,
            crate::remote_helper_protocol::FrameKind::HelloAck
        );
        crate::remote_helper_protocol::write_frame(
            &mut input,
            &crate::remote_helper_protocol::Frame {
                kind: crate::remote_helper_protocol::FrameKind::Close,
                request_id: 0,
                payload: Vec::new(),
            },
            64 * 1024,
        )
        .unwrap();
        input.flush().unwrap();
        drop(input);
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn persistent_bootstrap_round_trips_need_with_binary_bytes() {
        use std::io::{BufRead, BufReader, Write};
        use std::process::{Command, Stdio};
        use tempfile::TempDir;

        let (_helper_path, bytes) = helper_fixture();
        let identity = persistent_identity(&bytes);
        let home = TempDir::new().unwrap();
        let tmp = home.path().join("tmp");
        std::fs::create_dir_all(&tmp).unwrap();
        let target = home
            .path()
            .join(".local/share/codex-ssh-bridge/helpers")
            .join(&identity.version)
            .join(identity.target);
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("helper"), b"stale-helper").unwrap();
        std::fs::set_permissions(
            target.join("helper"),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let command = persistent_helper_command(64 * 1024, &identity).unwrap();
        let mut child = Command::new("/bin/sh")
            .args(["-c", &command])
            .env("HOME", home.path())
            .env("TMPDIR", &tmp)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut status = String::new();
        output.read_line(&mut status).unwrap();
        assert_eq!(status, "CXSB-INSTALL-1 NEED\n");
        input.write_all(&bytes).unwrap();
        input.flush().unwrap();
        let hello = crate::remote_helper_protocol::read_frame(&mut output, 64 * 1024)
            .unwrap()
            .unwrap();
        assert_eq!(
            hello.kind,
            crate::remote_helper_protocol::FrameKind::HelloAck
        );
        let installed = home
            .path()
            .join(".local/share/codex-ssh-bridge/helpers")
            .join(&identity.version)
            .join(identity.target)
            .join("helper");
        assert_eq!(std::fs::read(installed).unwrap(), bytes);
        crate::remote_helper_protocol::write_frame(
            &mut input,
            &crate::remote_helper_protocol::Frame {
                kind: crate::remote_helper_protocol::FrameKind::Close,
                request_id: 0,
                payload: Vec::new(),
            },
            64 * 1024,
        )
        .unwrap();
        input.flush().unwrap();
        drop(input);
        assert!(child.wait().unwrap().success());
    }
}
