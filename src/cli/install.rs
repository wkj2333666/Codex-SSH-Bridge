use std::ffi::{CString, OsStr, OsString};
use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use super::{LocalCommandSpec, run_local_command};
use crate::error::{BridgeError, BridgeResult};

const MCP_NAME: &str = "ssh-bridge";
const CODEX_PATH_WARNING: &str = "WARNING: proceeding, even though we could not create PATH aliases: Read-only file system (os error 30)";
const CODEX_MISSING: &str = "Error: No MCP server named 'ssh-bridge' found.";
const LOCAL_OUTPUT_LIMIT: usize = 1024 * 1024;
const LOCAL_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct InstallLayout {
    pub binary: PathBuf,
    pub stable_binary: PathBuf,
    pub plugin_manifest: PathBuf,
    pub mcp_manifest: PathBuf,
    pub skill_source: PathBuf,
    pub skill_target: PathBuf,
    pub identity_file: PathBuf,
    pub codex_executable: PathBuf,
    #[doc(hidden)]
    pub quarantine_delete_failure: Option<usize>,
}

impl InstallLayout {
    pub fn discover() -> BridgeResult<Self> {
        let binary = std::env::current_exe().map_err(BridgeError::io)?;
        let binary = fs::canonicalize(binary).map_err(BridgeError::io)?;
        let bin_directory = binary
            .parent()
            .ok_or_else(|| BridgeError::invalid_config("release binary has no parent directory"))?;
        if bin_directory.file_name() != Some(OsStr::new("bin")) {
            return Err(BridgeError::invalid_config(
                "install must run from the packaged bin/codex-ssh-bridge binary",
            ));
        }
        let bundle = bin_directory
            .parent()
            .ok_or_else(|| BridgeError::invalid_config("packaged binary has no bundle root"))?
            .to_owned();
        let home = nonempty_environment("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| BridgeError::invalid_config("HOME is required for --user install"))?;
        if !home.is_absolute() {
            return Err(BridgeError::invalid_config("HOME must be an absolute path"));
        }
        let state_base = nonempty_environment("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/state"));
        Ok(Self {
            binary,
            plugin_manifest: bundle.join(".codex-plugin/plugin.json"),
            stable_binary: home.join(".local/bin/codex-ssh-bridge"),
            mcp_manifest: bundle.join(".mcp.json.example"),
            skill_source: bundle.join("skills/remote-ssh-ops"),
            skill_target: home.join(".codex/skills/remote-ssh-ops"),
            identity_file: state_base.join("codex-ssh-bridge/install.toml"),
            codex_executable: find_executable("codex")?,
            quarantine_delete_failure: None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallReport {
    pub applied: bool,
    pub installation_id: String,
    pub actions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallationIdentity {
    version: u32,
    installation_id: String,
    binary: String,
    binary_sha256: String,
    #[serde(default)]
    stable_binary: Option<String>,
    plugin_manifest: String,
    plugin_sha256: String,
    mcp_manifest: String,
    mcp_sha256: String,
    skill_source: String,
    skill_sha256: String,
    skill_target: String,
    codex_executable: String,
}

#[derive(Debug, Clone)]
struct ResolvedInstall {
    layout: InstallLayout,
    identity: InstallationIdentity,
}

#[derive(Debug)]
struct InstallPreflight {
    resolved: ResolvedInstall,
    mcp: Presence,
    skill: Presence,
    marker: Presence,
    actions: Vec<String>,
}

struct InstallLock {
    _file: fs::File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MutationOutcome {
    Applied,
    NotApplied,
    Unknown,
}

struct MutationError {
    error: BridgeError,
    outcome: MutationOutcome,
}

#[derive(Debug)]
struct QuarantinedPath {
    original: PathBuf,
    quarantine: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Presence {
    Absent,
    Matching,
    NeedsUpdate,
}

async fn install_preflight(
    layout: InstallLayout,
    probe_mutations: bool,
) -> BridgeResult<InstallPreflight> {
    let resolved = resolve_layout(layout)?;
    validate_install_destinations(&resolved)?;
    let skill = skill_presence(&resolved)?;
    let marker = marker_presence(&resolved)?;
    if probe_mutations {
        if skill == Presence::Absent {
            probe_absent_destination(&resolved.layout.skill_target)?;
        } else if skill == Presence::NeedsUpdate {
            probe_parent_mutation(&resolved.layout.skill_target)?;
        }
        if marker == Presence::Absent {
            probe_absent_destination(&resolved.layout.identity_file)?;
        } else if marker == Presence::NeedsUpdate {
            probe_parent_mutation(&resolved.layout.identity_file)?;
        }
        probe_parent_mutation(&resolved.layout.stable_binary)?;
    }
    let mcp = codex_get(&resolved).await?;
    let actions = vec![
        match mcp {
            Presence::Absent => "register MCP ssh-bridge".to_owned(),
            Presence::Matching => "MCP ssh-bridge already matches".to_owned(),
            Presence::NeedsUpdate => "replace managed MCP ssh-bridge with stable path".to_owned(),
        },
        match skill {
            Presence::Absent => "create remote-ssh-ops Skill symlink".to_owned(),
            Presence::Matching => "remote-ssh-ops Skill symlink already matches".to_owned(),
            Presence::NeedsUpdate => {
                "replace managed remote-ssh-ops Skill with current symlink".to_owned()
            }
        },
        match marker {
            Presence::Absent => "write private installation identity".to_owned(),
            Presence::Matching => "installation identity already matches".to_owned(),
            Presence::NeedsUpdate => "replace managed installation identity".to_owned(),
        },
    ];
    Ok(InstallPreflight {
        resolved,
        mcp,
        skill,
        marker,
        actions,
    })
}

async fn uninstall_preflight(
    layout: InstallLayout,
    probe_mutations: bool,
) -> BridgeResult<InstallPreflight> {
    let resolved = resolve_layout(layout)?;
    validate_install_destinations(&resolved)?;
    let marker = marker_presence(&resolved)?;
    if marker != Presence::Matching {
        return Err(BridgeError::invalid_config(
            "recorded installation identity is missing",
        ));
    }
    let skill = skill_presence(&resolved)?;
    if probe_mutations {
        if skill == Presence::Matching {
            probe_parent_mutation(&resolved.layout.skill_target)?;
        }
        probe_parent_mutation(&resolved.layout.identity_file)?;
    }
    let mcp = codex_get(&resolved).await?;
    let actions = vec![
        match mcp {
            Presence::Absent => "MCP ssh-bridge is already absent".to_owned(),
            Presence::Matching => "remove identity-matching MCP ssh-bridge".to_owned(),
            Presence::NeedsUpdate => "MCP ssh-bridge is not this installation".to_owned(),
        },
        match skill {
            Presence::Absent => "remote-ssh-ops Skill symlink is already absent".to_owned(),
            Presence::Matching => "remove identity-matching Skill symlink".to_owned(),
            Presence::NeedsUpdate => "remote-ssh-ops Skill is not this installation".to_owned(),
        },
        "remove private installation identity".to_owned(),
    ];
    Ok(InstallPreflight {
        resolved,
        mcp,
        skill,
        marker,
        actions,
    })
}

fn validate_install_destinations(resolved: &ResolvedInstall) -> BridgeResult<()> {
    crate::config::validate_secure_existing_ancestors(&resolved.layout.skill_target)?;
    crate::config::validate_secure_existing_ancestors(&resolved.layout.identity_file)?;
    crate::config::validate_secure_existing_ancestors(&resolved.layout.stable_binary)?;
    Ok(())
}

fn install_lock_path(resolved: &ResolvedInstall) -> BridgeResult<PathBuf> {
    let home = resolved
        .layout
        .skill_target
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or_else(|| BridgeError::invalid_config("Skill destination has no user root"))?;
    Ok(home.join(".codex-ssh-bridge.install.lock"))
}

async fn acquire_install_lock(resolved: &ResolvedInstall) -> BridgeResult<InstallLock> {
    let path = install_lock_path(resolved)?;
    crate::config::validate_secure_existing_ancestors(&path)?;
    tokio::task::spawn_blocking(move || {
        let mut options = fs::OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options.open(&path).map_err(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) {
                BridgeError::invalid_config("installation lock must not be a symlink")
            } else {
                BridgeError::io(error)
            }
        })?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(BridgeError::io)?;
        let metadata = file.metadata().map_err(BridgeError::io)?;
        // SAFETY: geteuid has no preconditions and retains no pointers.
        let current_uid = unsafe { libc::geteuid() };
        if !metadata.is_file() || metadata.uid() != current_uid || metadata.mode() & 0o077 != 0 {
            return Err(BridgeError::invalid_config(
                "installation lock must be a private current-user-owned regular file",
            ));
        }
        let deadline = Instant::now() + LOCAL_TIMEOUT;
        loop {
            // SAFETY: flock receives a live descriptor and valid operation constants.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::WouldBlock {
                return Err(BridgeError::io(error));
            }
            if Instant::now() >= deadline {
                return Err(BridgeError::new(
                    crate::ErrorCode::CommandTimeout,
                    "timed out waiting for the user installation lock",
                    false,
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(InstallLock { _file: file })
    })
    .await
    .map_err(|error| BridgeError::io(format!("installation lock task failed: {error}")))?
}

pub async fn install_user(layout: InstallLayout, apply: bool) -> BridgeResult<InstallReport> {
    if !apply {
        let preliminary = install_preflight(layout, false).await?;
        return Ok(report(false, &preliminary.resolved, preliminary.actions));
    }
    let preliminary = resolve_layout(layout.clone())?;
    validate_install_destinations(&preliminary)?;
    let _lock = acquire_install_lock(&preliminary).await?;
    let preflight = install_preflight(layout, true).await?;
    let InstallPreflight {
        resolved,
        mcp,
        skill,
        marker,
        actions,
    } = preflight;

    let mut journal = InstallJournal::default();
    let applied = async {
        ensure_stable_binary(&resolved, &mut journal)?;

        if mcp == Presence::NeedsUpdate {
            if codex_get(&resolved).await? != Presence::NeedsUpdate {
                return Err(BridgeError::invalid_config(
                    "MCP entry changed after installation preflight",
                ));
            }
            match codex_remove_checked(&resolved).await {
                Ok(()) => journal.mcp_removed = true,
                Err(failure) if failure.outcome == MutationOutcome::Applied => {
                    journal.mcp_removed = true;
                    return Err(failure.error);
                }
                Err(failure) => return Err(failure.error),
            }
        }
        if mcp != Presence::Matching {
            if codex_get(&resolved).await? != Presence::Absent {
                return Err(BridgeError::invalid_config(
                    "MCP entry was not absent before registration",
                ));
            }
            if let Err(failure) = codex_add_checked(&resolved).await {
                if failure.outcome == MutationOutcome::Applied {
                    journal.mcp_added = true;
                }
                if failure.outcome == MutationOutcome::Unknown {
                    return Err(BridgeError::io(
                        "Codex MCP add outcome is unknown; rollback incomplete",
                    ));
                }
                return Err(failure.error);
            }
            journal.mcp_added = true;
        }
        if skill != Presence::Matching {
            if skill_presence(&resolved)? != skill {
                return Err(BridgeError::invalid_config(
                    "Skill destination changed after installation preflight",
                ));
            }
            let parent = resolved
                .layout
                .skill_target
                .parent()
                .expect("absolute Skill target has a parent");
            ensure_destination_directory(parent, &mut journal.created_directories)?;
            if skill == Presence::NeedsUpdate {
                journal.skill_quarantine = Some(quarantine_path(&resolved.layout.skill_target)?);
            }
            symlink(&resolved.layout.skill_source, &resolved.layout.skill_target)
                .map_err(BridgeError::io)?;
            journal.skill_created = true;
        }
        if marker != Presence::Matching {
            if marker_presence(&resolved)? != marker {
                return Err(BridgeError::invalid_config(
                    "installation identity changed after preflight",
                ));
            }
            let parent = resolved
                .layout
                .identity_file
                .parent()
                .expect("absolute identity path has a parent");
            ensure_destination_directory(parent, &mut journal.created_directories)?;
            if marker == Presence::NeedsUpdate {
                journal.marker_quarantine = Some(quarantine_path(&resolved.layout.identity_file)?);
            }
            write_identity_noclobber(&resolved)?;
            journal.marker_created = true;
        }
        Ok(())
    }
    .await;
    if let Err(error) = applied {
        if rollback_install(&resolved, &journal).await.is_err() {
            return Err(BridgeError::new(
                crate::ErrorCode::Io,
                "installation failed and rollback was incomplete",
                false,
            ));
        }
        return Err(error);
    }
    cleanup_install_quarantine(&mut journal)?;
    let mut actions = actions;
    let removed_releases = prune_old_releases(&resolved)?;
    if removed_releases > 0 {
        actions.push(format!(
            "remove {removed_releases} older managed release(s)"
        ));
    }
    Ok(report(true, &resolved, actions))
}

pub async fn uninstall_user(layout: InstallLayout, apply: bool) -> BridgeResult<InstallReport> {
    if !apply {
        let preliminary = uninstall_preflight(layout, false).await?;
        return Ok(report(false, &preliminary.resolved, preliminary.actions));
    }
    let preliminary = resolve_layout(layout.clone())?;
    validate_install_destinations(&preliminary)?;
    let _lock = acquire_install_lock(&preliminary).await?;
    let preflight = uninstall_preflight(layout, true).await?;
    let InstallPreflight {
        resolved,
        mcp,
        skill,
        actions,
        ..
    } = preflight;

    let mut mcp_removed = false;
    let mut skill_quarantine = None;
    let mut marker_quarantine = None;
    let removed = async {
        if mcp == Presence::Matching {
            if codex_get(&resolved).await? != Presence::Matching {
                return Err(BridgeError::invalid_config(
                    "MCP entry changed after uninstall preflight",
                ));
            }
            match codex_remove_checked(&resolved).await {
                Ok(()) => mcp_removed = true,
                Err(failure) if failure.outcome == MutationOutcome::Applied => {
                    mcp_removed = true;
                    return Err(failure.error);
                }
                Err(failure) if failure.outcome == MutationOutcome::NotApplied => {
                    return Err(failure.error);
                }
                Err(_) => {
                    return Err(BridgeError::io(
                        "Codex MCP removal outcome is unknown; rollback incomplete",
                    ));
                }
            }
        }
        if skill == Presence::Matching {
            if skill_presence(&resolved)? != Presence::Matching {
                return Err(BridgeError::invalid_config(
                    "Skill destination changed after uninstall preflight",
                ));
            }
            skill_quarantine = Some(quarantine_path(&resolved.layout.skill_target)?);
        }
        if marker_presence(&resolved)? != Presence::Matching {
            return Err(BridgeError::invalid_config(
                "installation identity changed after uninstall preflight",
            ));
        }
        marker_quarantine = Some(quarantine_path(&resolved.layout.identity_file)?);
        Ok(())
    }
    .await;
    if let Err(error) = removed {
        if rollback_uninstall(
            &resolved,
            mcp_removed,
            skill_quarantine.as_ref(),
            marker_quarantine.as_ref(),
            false,
            false,
        )
        .await
        .is_err()
        {
            return Err(BridgeError::new(
                crate::ErrorCode::Io,
                "uninstall failed and rollback was incomplete",
                false,
            ));
        }
        return Err(error);
    }
    let mut marker_deleted = false;
    let mut skill_deleted = false;
    let mut deletion_index = 0usize;
    let cleanup = (|| {
        if let Some(quarantine) = marker_quarantine.as_ref() {
            deletion_index += 1;
            remove_quarantine(
                quarantine,
                deletion_index,
                resolved.layout.quarantine_delete_failure,
            )?;
            marker_deleted = true;
        }
        if let Some(quarantine) = skill_quarantine.as_ref() {
            deletion_index += 1;
            remove_quarantine(
                quarantine,
                deletion_index,
                resolved.layout.quarantine_delete_failure,
            )?;
            skill_deleted = true;
        }
        Ok(())
    })();
    if let Err(error) = cleanup {
        if rollback_uninstall(
            &resolved,
            mcp_removed,
            skill_quarantine.as_ref(),
            marker_quarantine.as_ref(),
            skill_deleted,
            marker_deleted,
        )
        .await
        .is_err()
        {
            return Err(BridgeError::new(
                crate::ErrorCode::Io,
                "uninstall cleanup failed and rollback was incomplete",
                false,
            ));
        }
        return Err(error);
    }
    Ok(report(true, &resolved, actions))
}

fn remove_quarantine(
    quarantine: &QuarantinedPath,
    deletion_index: usize,
    injected_failure: Option<usize>,
) -> BridgeResult<()> {
    if injected_failure == Some(deletion_index) {
        return Err(BridgeError::io("injected quarantine deletion failure"));
    }
    fs::remove_file(&quarantine.quarantine).map_err(BridgeError::io)
}

async fn rollback_uninstall(
    resolved: &ResolvedInstall,
    mcp_removed: bool,
    skill_quarantine: Option<&QuarantinedPath>,
    marker_quarantine: Option<&QuarantinedPath>,
    skill_deleted: bool,
    marker_deleted: bool,
) -> BridgeResult<()> {
    let mut failed = false;
    if marker_deleted {
        if !matches!(marker_presence(resolved), Ok(Presence::Absent))
            || write_identity_noclobber(resolved).is_err()
        {
            failed = true;
        }
    } else if let Some(quarantine) = marker_quarantine
        && restore_quarantine(quarantine).is_err()
    {
        failed = true;
    }
    if skill_deleted {
        if !matches!(skill_presence(resolved), Ok(Presence::Absent))
            || symlink(&resolved.layout.skill_source, &resolved.layout.skill_target).is_err()
        {
            failed = true;
        }
    } else if let Some(quarantine) = skill_quarantine
        && restore_quarantine(quarantine).is_err()
    {
        failed = true;
    }
    if mcp_removed {
        match codex_add_checked(resolved).await {
            Ok(()) => {}
            Err(error) if error.outcome == MutationOutcome::Applied => {}
            Err(_) => failed = true,
        }
    }
    if failed {
        Err(BridgeError::io(
            "uninstall rollback could not restore every mutation",
        ))
    } else {
        Ok(())
    }
}

#[derive(Default)]
struct InstallJournal {
    mcp_added: bool,
    mcp_removed: bool,
    stable_created: bool,
    stable_quarantine: Option<QuarantinedPath>,
    skill_created: bool,
    skill_quarantine: Option<QuarantinedPath>,
    marker_created: bool,
    marker_quarantine: Option<QuarantinedPath>,
    created_directories: Vec<PathBuf>,
}

fn ensure_stable_binary(
    resolved: &ResolvedInstall,
    journal: &mut InstallJournal,
) -> BridgeResult<()> {
    let destination = &resolved.layout.stable_binary;
    let parent = destination
        .parent()
        .ok_or_else(|| BridgeError::invalid_config("stable binary path has no parent"))?;
    ensure_destination_directory(parent, &mut journal.created_directories)?;

    match fs::symlink_metadata(destination) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            if fs::canonicalize(destination).ok().as_deref()
                == Some(resolved.layout.binary.as_path())
            {
                return Ok(());
            }
            let Some(home) = destination
                .parent()
                .and_then(Path::parent)
                .and_then(Path::parent)
            else {
                return Err(BridgeError::invalid_config(
                    "stable binary path has no user root",
                ));
            };
            let managed_root = home.join(".local/share/codex-ssh-bridge");
            let target = fs::canonicalize(destination)
                .map_err(|_| BridgeError::invalid_config("stable binary symlink is dangling"))?;
            if !target.starts_with(&managed_root)
                || target.file_name() != Some(OsStr::new("codex-ssh-bridge"))
            {
                return Err(BridgeError::invalid_config(
                    "stable binary symlink points outside bridge-managed releases",
                ));
            }
            journal.stable_quarantine = Some(quarantine_path(destination)?);
        }
        Ok(_) => {
            return Err(BridgeError::invalid_config(
                "stable binary destination exists and is not a symlink",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(BridgeError::io(error)),
    }

    let temporary = parent.join(format!(
        ".codex-ssh-bridge.binary.{}.{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    symlink(&resolved.layout.binary, &temporary).map_err(BridgeError::io)?;
    if let Err(error) = fs::rename(&temporary, destination) {
        let _ = fs::remove_file(&temporary);
        return Err(BridgeError::io(error));
    }
    journal.stable_created = true;
    Ok(())
}

fn cleanup_install_quarantine(journal: &mut InstallJournal) -> BridgeResult<()> {
    for quarantine in [
        journal.stable_quarantine.take(),
        journal.skill_quarantine.take(),
        journal.marker_quarantine.take(),
    ]
    .into_iter()
    .flatten()
    {
        remove_quarantine_tree(&quarantine.quarantine)?;
    }
    Ok(())
}

fn remove_quarantine_tree(path: &Path) -> BridgeResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(BridgeError::io)?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path).map_err(BridgeError::io)
    } else {
        fs::remove_file(path).map_err(BridgeError::io)
    }
}

fn prune_old_releases(resolved: &ResolvedInstall) -> BridgeResult<usize> {
    let Some(home) = resolved
        .layout
        .stable_binary
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
    else {
        return Err(BridgeError::invalid_config(
            "stable binary path has no user root",
        ));
    };
    let releases = home.join(".local/share/codex-ssh-bridge");
    let entries = match fs::read_dir(&releases) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(BridgeError::io(error)),
    };
    let current_bundle = resolved
        .layout
        .binary
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| BridgeError::invalid_config("packaged binary has no bundle root"))?;
    let mut removed = 0;
    for entry in entries {
        let path = entry.map_err(BridgeError::io)?.path();
        if path == current_bundle {
            continue;
        }
        let metadata = fs::symlink_metadata(&path).map_err(BridgeError::io)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            continue;
        }
        let binary = path.join("bin/codex-ssh-bridge");
        let manifest = path.join(".codex-plugin/plugin.json");
        if fs::symlink_metadata(&binary)
            .is_ok_and(|value| value.is_file() && !value.file_type().is_symlink())
            && fs::symlink_metadata(&manifest)
                .is_ok_and(|value| value.is_file() && !value.file_type().is_symlink())
        {
            fs::remove_dir_all(path).map_err(BridgeError::io)?;
            removed += 1;
        }
    }
    Ok(removed)
}

async fn rollback_install(
    resolved: &ResolvedInstall,
    journal: &InstallJournal,
) -> BridgeResult<()> {
    let mut failed = false;
    if journal.marker_created
        && matches!(marker_presence(resolved), Ok(Presence::Matching))
        && quarantine_then_remove(&resolved.layout.identity_file).is_err()
    {
        failed = true;
    }
    if journal.skill_created
        && matches!(skill_presence(resolved), Ok(Presence::Matching))
        && quarantine_then_remove(&resolved.layout.skill_target).is_err()
    {
        failed = true;
    }
    if journal.marker_quarantine.is_some()
        && journal.marker_created
        && matches!(marker_presence(resolved), Ok(Presence::Matching))
        && quarantine_then_remove(&resolved.layout.identity_file).is_err()
    {
        failed = true;
    }
    if journal.mcp_added {
        match codex_get(resolved).await {
            Ok(Presence::Matching) => match codex_remove_checked(resolved).await {
                Ok(()) => {}
                Err(error) if error.outcome == MutationOutcome::Applied => {}
                Err(_) => failed = true,
            },
            Ok(Presence::Absent) => {}
            Err(error) if error.code == crate::ErrorCode::InvalidConfig => {
                // A concurrently replaced entry is not ours to remove.
            }
            Err(_) => failed = true,
        }
    }
    if journal.mcp_removed {
        match codex_get(resolved).await {
            Ok(Presence::Absent) => {
                if codex_add_checked(resolved).await.is_err() {
                    failed = true;
                }
            }
            Ok(Presence::Matching) => {}
            Ok(Presence::NeedsUpdate) => failed = true,
            Err(_) => failed = true,
        }
    }
    if journal.stable_created {
        if fs::remove_file(&resolved.layout.stable_binary).is_err() {
            failed = true;
        }
    }
    if let Some(quarantine) = journal.stable_quarantine.as_ref() {
        if restore_quarantine(quarantine).is_err() {
            failed = true;
        }
    }
    if let Some(quarantine) = journal.skill_quarantine.as_ref() {
        if restore_quarantine(quarantine).is_err() {
            failed = true;
        }
    }
    if let Some(quarantine) = journal.marker_quarantine.as_ref() {
        if restore_quarantine(quarantine).is_err() {
            failed = true;
        }
    }
    for directory in journal.created_directories.iter().rev() {
        if let Err(error) = fs::remove_dir(directory)
            && error.kind() != std::io::ErrorKind::NotFound
            && error.kind() != std::io::ErrorKind::DirectoryNotEmpty
        {
            failed = true;
        }
    }
    if failed {
        Err(BridgeError::io("rollback could not restore every mutation"))
    } else {
        Ok(())
    }
}

fn ensure_destination_directory(path: &Path, created: &mut Vec<PathBuf>) -> BridgeResult<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    use std::path::Component;

    // SAFETY: credential getters have no preconditions and retain no pointers.
    let current_uid = unsafe { libc::geteuid() };
    let root_uid = fs::symlink_metadata("/").map_err(BridgeError::io)?.uid();
    let mut resolved = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => resolved.push(name),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(BridgeError::invalid_config(
                    "installation destination must be normalized and absolute",
                ));
            }
        }
        let metadata = match fs::symlink_metadata(&resolved) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700);
                match builder.create(&resolved) {
                    Ok(()) => created.push(resolved.clone()),
                    Err(create_error)
                        if create_error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(create_error) => return Err(BridgeError::io(create_error)),
                }
                fs::symlink_metadata(&resolved).map_err(BridgeError::io)?
            }
            Err(error) => return Err(BridgeError::io(error)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(BridgeError::invalid_config(
                "installation destination ancestors must be real directories",
            ));
        }
        if metadata.uid() != current_uid && metadata.uid() != root_uid {
            return Err(BridgeError::invalid_config(
                "installation destination ancestors must be owned by root or the current user",
            ));
        }
        let trusted_tmp = resolved == Path::new("/tmp")
            && metadata.uid() == root_uid
            && metadata.mode() & 0o1000 != 0;
        if metadata.mode() & 0o022 != 0 && !trusted_tmp {
            return Err(BridgeError::invalid_config(
                "installation destination ancestors must not be writable by group or other users",
            ));
        }
    }
    Ok(())
}

fn probe_absent_destination(path: &Path) -> BridgeResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| BridgeError::invalid_config("installation destination has no parent"))?;
    let mut created = Vec::new();
    let mut placeholder_created = false;
    let probed = (|| {
        ensure_destination_directory(parent, &mut created)?;
        let mut options = fs::OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let placeholder = options.open(path).map_err(BridgeError::io)?;
        placeholder_created = true;
        placeholder
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(BridgeError::io)?;
        drop(placeholder);
        fs::remove_file(path).map_err(BridgeError::io)?;
        placeholder_created = false;
        Ok(())
    })();
    let mut cleanup_failed = false;
    if placeholder_created && fs::remove_file(path).is_err() {
        cleanup_failed = true;
    }
    for directory in created.iter().rev() {
        if let Err(error) = fs::remove_dir(directory)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            cleanup_failed = true;
        }
    }
    if cleanup_failed {
        return Err(BridgeError::io(
            "destination creation probe cleanup was incomplete",
        ));
    }
    probed
}

fn probe_parent_mutation(path: &Path) -> BridgeResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| BridgeError::invalid_config("installation destination has no parent"))?;
    for _ in 0..32 {
        let probe = parent.join(format!(
            ".codex-ssh-bridge.probe.{}.{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let mut options = fs::OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        match options.open(&probe) {
            Ok(file) => {
                drop(file);
                fs::remove_file(&probe).map_err(BridgeError::io)?;
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(BridgeError::io(error)),
        }
    }
    Err(BridgeError::io(
        "could not reserve a destination mutation probe",
    ))
}

fn quarantine_path(path: &Path) -> BridgeResult<QuarantinedPath> {
    let parent = path
        .parent()
        .ok_or_else(|| BridgeError::invalid_config("quarantine target has no parent"))?;
    for _ in 0..32 {
        let quarantine = parent.join(format!(
            ".codex-ssh-bridge.quarantine.{}.{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        match rename_noreplace(path, &quarantine) {
            Ok(()) => {
                return Ok(QuarantinedPath {
                    original: path.to_owned(),
                    quarantine,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(BridgeError::io(error)),
        }
    }
    Err(BridgeError::io("could not reserve a quarantine name"))
}

fn restore_quarantine(quarantine: &QuarantinedPath) -> BridgeResult<()> {
    rename_noreplace(&quarantine.quarantine, &quarantine.original).map_err(BridgeError::io)
}

fn quarantine_then_remove(path: &Path) -> BridgeResult<()> {
    let quarantine = quarantine_path(path)?;
    fs::remove_file(quarantine.quarantine).map_err(BridgeError::io)
}

fn rename_noreplace(source: &Path, destination: &Path) -> std::io::Result<()> {
    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let destination = CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: both C strings are NUL-terminated and remain alive for the syscall.
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn resolve_layout(layout: InstallLayout) -> BridgeResult<ResolvedInstall> {
    let binary = canonical_secure_file(&layout.binary, true)?;
    let plugin_manifest = canonical_secure_file(&layout.plugin_manifest, false)?;
    let mcp_manifest = canonical_secure_file(&layout.mcp_manifest, false)?;
    let codex_executable = canonical_secure_codex_executable(&layout.codex_executable)?;
    let skill_source = canonical_secure_directory(&layout.skill_source)?;
    for required in ["SKILL.md", "agents/openai.yaml", "references/operations.md"] {
        canonical_secure_file(&skill_source.join(required), false)?;
    }
    validate_package_layout(&binary, &plugin_manifest, &mcp_manifest, &skill_source)?;
    if !layout.skill_target.is_absolute()
        || !layout.identity_file.is_absolute()
        || !layout.stable_binary.is_absolute()
    {
        return Err(BridgeError::invalid_config(
            "installation destinations must be absolute paths",
        ));
    }
    let binary_hash = sha256_file(&binary)?;
    let plugin_hash = sha256_file(&plugin_manifest)?;
    let mcp_hash = sha256_file(&mcp_manifest)?;
    let skill_hash = hash_secure_skill_tree(&skill_source)?;
    let strings = [
        path_string(&binary)?,
        binary_hash.clone(),
        path_string(&layout.stable_binary)?,
        path_string(&plugin_manifest)?,
        plugin_hash.clone(),
        path_string(&mcp_manifest)?,
        mcp_hash.clone(),
        path_string(&skill_source)?,
        skill_hash.clone(),
        path_string(&layout.skill_target)?,
        path_string(&codex_executable)?,
    ];
    let mut id_hasher = Sha256::new();
    id_hasher.update(b"codex-ssh-bridge-installation-v1\0");
    for value in &strings {
        id_hasher.update((value.len() as u64).to_be_bytes());
        id_hasher.update(value.as_bytes());
    }
    let identity = InstallationIdentity {
        version: 1,
        installation_id: hex_digest(&id_hasher.finalize()),
        binary: strings[0].clone(),
        binary_sha256: binary_hash,
        stable_binary: Some(strings[2].clone()),
        plugin_manifest: strings[3].clone(),
        plugin_sha256: plugin_hash,
        mcp_manifest: strings[5].clone(),
        mcp_sha256: mcp_hash,
        skill_source: strings[7].clone(),
        skill_sha256: skill_hash,
        skill_target: strings[9].clone(),
        codex_executable: strings[10].clone(),
    };
    Ok(ResolvedInstall {
        layout: InstallLayout {
            binary,
            stable_binary: layout.stable_binary,
            plugin_manifest,
            mcp_manifest,
            skill_source,
            skill_target: layout.skill_target,
            identity_file: layout.identity_file,
            codex_executable,
            quarantine_delete_failure: layout.quarantine_delete_failure,
        },
        identity,
    })
}

fn validate_package_layout(
    binary: &Path,
    plugin_manifest: &Path,
    mcp_manifest: &Path,
    skill_source: &Path,
) -> BridgeResult<()> {
    let plugin_directory = plugin_manifest
        .parent()
        .ok_or_else(|| BridgeError::invalid_config("plugin manifest has no parent"))?;
    if plugin_directory.file_name() != Some(OsStr::new(".codex-plugin")) {
        return Err(BridgeError::invalid_config(
            "plugin manifest is not under .codex-plugin",
        ));
    }
    let bundle = plugin_directory
        .parent()
        .ok_or_else(|| BridgeError::invalid_config("plugin manifest has no bundle root"))?;
    if plugin_manifest != bundle.join(".codex-plugin/plugin.json")
        || binary != bundle.join("bin/codex-ssh-bridge")
        || mcp_manifest != bundle.join(".mcp.json.example")
        || skill_source != bundle.join("skills/remote-ssh-ops")
    {
        return Err(BridgeError::invalid_config(
            "installation files do not form one canonical packaged bundle",
        ));
    }

    let plugin = read_json_bounded(plugin_manifest, 256 * 1024, "plugin manifest")?;
    if plugin.get("name").and_then(serde_json::Value::as_str) != Some("codex-ssh-bridge")
        || plugin.get("skills").and_then(serde_json::Value::as_str) != Some("./skills/")
        || plugin.get("mcpServers").is_some()
    {
        return Err(BridgeError::invalid_config(
            "plugin manifest does not describe codex-ssh-bridge",
        ));
    }

    let mcp = read_json_bounded(mcp_manifest, 256 * 1024, "MCP manifest")?;
    let server = mcp
        .get("mcpServers")
        .and_then(|servers| servers.get(MCP_NAME))
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| BridgeError::invalid_config("MCP manifest has no ssh-bridge server"))?;
    if server.get("command").and_then(serde_json::Value::as_str)
        != Some("/absolute/path/to/target/release/codex-ssh-bridge")
        || server.get("args") != Some(&serde_json::json!(["mcp"]))
    {
        return Err(BridgeError::invalid_config(
            "MCP manifest does not launch the packaged Rust bridge",
        ));
    }

    let skill_document = read_bounded(&skill_source.join("SKILL.md"), 256 * 1024)?;
    let skill_document = std::str::from_utf8(&skill_document)
        .map_err(|_| BridgeError::invalid_config("Skill manifest is not UTF-8"))?;
    if skill_frontmatter_name(skill_document).as_deref() != Some("remote-ssh-ops") {
        return Err(BridgeError::invalid_config(
            "Skill manifest name is not remote-ssh-ops",
        ));
    }
    let agent = read_bounded(&skill_source.join("agents/openai.yaml"), 256 * 1024)?;
    let agent: AgentMetadata = serde_yaml::from_slice(&agent)
        .map_err(|_| BridgeError::invalid_config("Skill agent metadata is not valid YAML"))?;
    if !agent
        .dependencies
        .tools
        .iter()
        .any(|tool| tool.kind == "mcp" && tool.value == MCP_NAME && tool.transport == "stdio")
    {
        return Err(BridgeError::invalid_config(
            "Skill agent metadata does not declare the stdio MCP ssh-bridge dependency",
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct AgentMetadata {
    dependencies: AgentDependencies,
}

#[derive(Debug, Deserialize)]
struct AgentDependencies {
    tools: Vec<AgentToolDependency>,
}

#[derive(Debug, Deserialize)]
struct AgentToolDependency {
    #[serde(rename = "type")]
    kind: String,
    value: String,
    transport: String,
}

fn read_json_bounded(path: &Path, maximum: u64, label: &str) -> BridgeResult<serde_json::Value> {
    let bytes = read_bounded(path, maximum)?;
    serde_json::from_slice(&bytes)
        .map_err(|_| BridgeError::invalid_config(format!("{label} is not valid JSON")))
}

fn skill_frontmatter_name(document: &str) -> Option<String> {
    let mut lines = document.lines();
    if lines.next()? != "---" {
        return None;
    }
    let mut name = None;
    for line in lines {
        if line == "---" {
            return name;
        }
        if let Some(value) = line.strip_prefix("name:") {
            if name.is_some() {
                return None;
            }
            name = Some(value.trim().trim_matches(['\'', '"']).to_owned());
        }
    }
    None
}

async fn codex_get(resolved: &ResolvedInstall) -> BridgeResult<Presence> {
    let output = run_codex(resolved, ["mcp", "get", MCP_NAME, "--json"]).await?;
    if output.status == 1 && output.stdout.is_empty() && codex_missing(&output.stderr) {
        return Ok(Presence::Absent);
    }
    if output.status != 0 {
        return Err(BridgeError::io(
            "`codex mcp get` failed; it was not classified as not-found",
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| BridgeError::io("`codex mcp get --json` returned invalid JSON"))?;
    if mcp_matches(
        &value,
        &resolved.layout.stable_binary,
        &resolved.layout.binary,
    )? {
        return Ok(Presence::Matching);
    }
    if managed_mcp_needs_update(&value, resolved)? {
        return Ok(Presence::NeedsUpdate);
    }
    {
        return Err(BridgeError::invalid_config(
            "an MCP server named ssh-bridge has a different configuration",
        ));
    }
}

fn codex_missing(stderr: &[u8]) -> bool {
    let Ok(stderr) = std::str::from_utf8(stderr) else {
        return false;
    };
    let mut warning_seen = false;
    let remaining: Vec<&str> = stderr
        .trim()
        .lines()
        .filter(|line| {
            if !warning_seen && *line == CODEX_PATH_WARNING {
                warning_seen = true;
                false
            } else {
                true
            }
        })
        .collect();
    remaining == [CODEX_MISSING]
}

fn mcp_matches(
    value: &serde_json::Value,
    stable_binary: &Path,
    binary: &Path,
) -> BridgeResult<bool> {
    let Some(transport) = value
        .get("transport")
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(false);
    };
    if transport.get("type").and_then(serde_json::Value::as_str) != Some("stdio") {
        return Ok(false);
    }
    let Some(command) = transport.get("command").and_then(serde_json::Value::as_str) else {
        return Ok(false);
    };
    let command = match fs::canonicalize(command) {
        Ok(command) => command,
        Err(_) => return Ok(false),
    };
    if command != binary && command != stable_binary {
        return Ok(false);
    }
    if transport.get("args") != Some(&serde_json::json!(["mcp"])) {
        return Ok(false);
    }
    if !null_or_empty_object(transport.get("env"))
        || !transport.get("cwd").is_none_or(serde_json::Value::is_null)
    {
        return Ok(false);
    }
    Ok(true)
}

fn managed_mcp_needs_update(
    value: &serde_json::Value,
    resolved: &ResolvedInstall,
) -> BridgeResult<bool> {
    let Some(transport) = value
        .get("transport")
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(false);
    };
    if transport.get("type").and_then(serde_json::Value::as_str) != Some("stdio")
        || transport.get("args") != Some(&serde_json::json!(["mcp"]))
        || !null_or_empty_object(transport.get("env"))
        || !transport.get("cwd").is_none_or(serde_json::Value::is_null)
    {
        return Ok(false);
    }
    let Some(command) = transport.get("command").and_then(serde_json::Value::as_str) else {
        return Ok(false);
    };
    let command = PathBuf::from(command);
    if command.file_name() != Some(OsStr::new("codex-ssh-bridge")) {
        return Ok(false);
    }
    let Some(home) = resolved
        .layout
        .stable_binary
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
    else {
        return Ok(false);
    };
    let managed_root = home.join(".local/share/codex-ssh-bridge");
    let command = fs::canonicalize(command)
        .map_err(|_| BridgeError::invalid_config("managed MCP command path is missing"))?;
    Ok(command.starts_with(&managed_root) && command != resolved.layout.binary)
}

fn null_or_empty_object(value: Option<&serde_json::Value>) -> bool {
    value.is_none_or(|value| {
        value.is_null() || value.as_object().is_some_and(serde_json::Map::is_empty)
    })
}

async fn codex_add_checked(resolved: &ResolvedInstall) -> Result<(), MutationError> {
    let binary = path_string(&resolved.layout.stable_binary).map_err(|error| MutationError {
        error,
        outcome: MutationOutcome::NotApplied,
    })?;
    let attempted = run_codex_os(
        resolved,
        vec![
            OsString::from("mcp"),
            OsString::from("add"),
            OsString::from(MCP_NAME),
            OsString::from("--"),
            OsString::from(binary),
            OsString::from("mcp"),
        ],
    )
    .await;
    let command_succeeded = matches!(&attempted, Ok(output) if output.status == 0);
    let failure = match attempted {
        Ok(output) if output.status == 0 => {
            BridgeError::io("`codex mcp add` reported success without a matching final state")
        }
        Ok(_) => BridgeError::io("`codex mcp add` failed"),
        Err(error) => error,
    };
    let outcome = match codex_get(resolved).await {
        Ok(Presence::Matching) if command_succeeded => return Ok(()),
        Ok(Presence::Matching) => MutationOutcome::Applied,
        Ok(Presence::Absent) => MutationOutcome::NotApplied,
        Ok(Presence::NeedsUpdate) => MutationOutcome::Unknown,
        Err(_) => MutationOutcome::Unknown,
    };
    Err(MutationError {
        error: failure,
        outcome,
    })
}

async fn codex_remove_checked(resolved: &ResolvedInstall) -> Result<(), MutationError> {
    let attempted = run_codex(resolved, ["mcp", "remove", MCP_NAME]).await;
    let command_succeeded = matches!(&attempted, Ok(output) if output.status == 0);
    let failure = match attempted {
        Ok(output) if output.status == 0 => {
            BridgeError::io("`codex mcp remove` reported success without an absent final state")
        }
        Ok(_) => BridgeError::io("`codex mcp remove` failed"),
        Err(error) => error,
    };
    let outcome = match codex_get(resolved).await {
        Ok(Presence::Absent) if command_succeeded => return Ok(()),
        Ok(Presence::Absent) => MutationOutcome::Applied,
        Ok(Presence::Matching) => MutationOutcome::NotApplied,
        Ok(Presence::NeedsUpdate) => MutationOutcome::Unknown,
        Err(_) => MutationOutcome::Unknown,
    };
    Err(MutationError {
        error: failure,
        outcome,
    })
}

async fn run_codex<const N: usize>(
    resolved: &ResolvedInstall,
    arguments: [&str; N],
) -> BridgeResult<super::LocalCommandOutput> {
    run_codex_os(
        resolved,
        arguments.into_iter().map(OsString::from).collect(),
    )
    .await
}

async fn run_codex_os(
    resolved: &ResolvedInstall,
    arguments: Vec<OsString>,
) -> BridgeResult<super::LocalCommandOutput> {
    run_local_command(LocalCommandSpec {
        executable: resolved.layout.codex_executable.clone(),
        arguments,
        timeout: LOCAL_TIMEOUT,
        max_output_bytes: LOCAL_OUTPUT_LIMIT,
    })
    .await
}

fn skill_presence(resolved: &ResolvedInstall) -> BridgeResult<Presence> {
    match fs::symlink_metadata(&resolved.layout.skill_target) {
        Ok(metadata) => {
            if !metadata.file_type().is_symlink() {
                if metadata.is_dir()
                    && hash_secure_skill_tree(&resolved.layout.skill_target)?
                        == resolved.identity.skill_sha256
                {
                    return Ok(Presence::NeedsUpdate);
                }
                return Err(BridgeError::invalid_config(
                    "Skill destination exists and is not a bridge-managed Skill",
                ));
            }
            let target = fs::canonicalize(&resolved.layout.skill_target).map_err(|_| {
                BridgeError::invalid_config("Skill destination symlink is dangling")
            })?;
            if target != resolved.layout.skill_source {
                return Err(BridgeError::invalid_config(
                    "Skill destination resolves to a different source",
                ));
            }
            Ok(Presence::Matching)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Presence::Absent),
        Err(error) => Err(BridgeError::io(error)),
    }
}

fn marker_presence(resolved: &ResolvedInstall) -> BridgeResult<Presence> {
    match fs::symlink_metadata(&resolved.layout.identity_file) {
        Ok(metadata) => {
            validate_private_identity_file(&metadata)?;
            let contents = read_bounded(&resolved.layout.identity_file, 64 * 1024)?;
            let identity: InstallationIdentity =
                toml::from_str(std::str::from_utf8(&contents).map_err(|_| {
                    BridgeError::invalid_config("installation identity is not UTF-8")
                })?)
                .map_err(|_| BridgeError::invalid_config("installation identity is invalid"))?;
            if identity != resolved.identity {
                if managed_identity(&identity, resolved) {
                    return Ok(Presence::NeedsUpdate);
                }
                return Err(BridgeError::invalid_config(
                    "recorded installation identity differs from this bundle",
                ));
            }
            Ok(Presence::Matching)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Presence::Absent),
        Err(error) => Err(BridgeError::io(error)),
    }
}

fn managed_identity(identity: &InstallationIdentity, resolved: &ResolvedInstall) -> bool {
    if identity.version != 1
        || !identity.binary.ends_with("/codex-ssh-bridge")
        || !identity.skill_source.ends_with("/skills/remote-ssh-ops")
        || !identity.skill_target.ends_with("/remote-ssh-ops")
    {
        return false;
    }
    let Some(home) = resolved
        .layout
        .stable_binary
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
    else {
        return false;
    };
    Path::new(&identity.binary).starts_with(home.join(".local/share/codex-ssh-bridge"))
        && Path::new(&identity.skill_source).starts_with(home.join(".local/share/codex-ssh-bridge"))
}

fn write_identity_noclobber(resolved: &ResolvedInstall) -> BridgeResult<()> {
    let parent = resolved
        .layout
        .identity_file
        .parent()
        .expect("identity path has parent");
    let serialized = toml::to_string_pretty(&resolved.identity)
        .map_err(|_| BridgeError::io("cannot serialize installation identity"))?;
    let mut temporary = NamedTempFile::new_in(parent).map_err(BridgeError::io)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(BridgeError::io)?;
    temporary
        .write_all(serialized.as_bytes())
        .map_err(BridgeError::io)?;
    temporary.flush().map_err(BridgeError::io)?;
    temporary.as_file().sync_all().map_err(BridgeError::io)?;
    temporary
        .persist_noclobber(&resolved.layout.identity_file)
        .map_err(|error| BridgeError::io(error.error))?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(BridgeError::io)?;
    Ok(())
}

fn canonical_secure_file(path: &Path, executable: bool) -> BridgeResult<PathBuf> {
    validate_trusted_ancestors(path)?;
    let original_metadata = fs::symlink_metadata(path).map_err(BridgeError::io)?;
    if original_metadata.file_type().is_symlink() {
        return Err(BridgeError::invalid_config(
            "installation sources must not be symlinks",
        ));
    }
    validate_trusted_source_file(&original_metadata, executable)?;
    let canonical = fs::canonicalize(path).map_err(BridgeError::io)?;
    validate_trusted_ancestors(&canonical)?;
    let metadata = fs::symlink_metadata(&canonical).map_err(BridgeError::io)?;
    validate_trusted_source_file(&metadata, executable)?;
    Ok(canonical)
}

fn canonical_secure_codex_executable(path: &Path) -> BridgeResult<PathBuf> {
    validate_trusted_ancestors(path)?;
    let entry_metadata = fs::symlink_metadata(path).map_err(BridgeError::io)?;
    if entry_metadata.file_type().is_symlink() {
        // SAFETY: geteuid has no preconditions and retains no pointers.
        let current_uid = unsafe { libc::geteuid() };
        let root_uid = fs::symlink_metadata("/").map_err(BridgeError::io)?.uid();
        if !trusted_source_owner(entry_metadata.uid(), current_uid, root_uid) {
            return Err(BridgeError::invalid_config(
                "Codex executable symlink must be owned by root or the current user",
            ));
        }
    } else {
        validate_trusted_source_file(&entry_metadata, true)?;
    }

    let canonical = fs::canonicalize(path).map_err(BridgeError::io)?;
    validate_trusted_ancestors(&canonical)?;
    let target_metadata = fs::symlink_metadata(&canonical).map_err(BridgeError::io)?;
    validate_trusted_source_file(&target_metadata, true)?;
    Ok(canonical)
}

fn canonical_secure_directory(path: &Path) -> BridgeResult<PathBuf> {
    validate_trusted_ancestors(path)?;
    let original_metadata = fs::symlink_metadata(path).map_err(BridgeError::io)?;
    if original_metadata.file_type().is_symlink() {
        return Err(BridgeError::invalid_config(
            "installation sources must not be symlinks",
        ));
    }
    validate_trusted_source_directory(&original_metadata)?;
    let canonical = fs::canonicalize(path).map_err(BridgeError::io)?;
    validate_trusted_ancestors(&canonical)?;
    validate_trusted_source_directory(&fs::symlink_metadata(&canonical).map_err(BridgeError::io)?)?;
    Ok(canonical)
}

fn validate_trusted_ancestors(path: &Path) -> BridgeResult<()> {
    use std::path::Component;

    if !path.is_absolute() {
        return Err(BridgeError::invalid_config(
            "installation source must resolve to an absolute path",
        ));
    }
    // SAFETY: credential getters have no preconditions and retain no pointers.
    let current_uid = unsafe { libc::geteuid() };
    let root_uid = fs::symlink_metadata("/").map_err(BridgeError::io)?.uid();
    let mut resolved = PathBuf::from("/");
    let mut below_private_user_ancestor = false;
    for component in path.parent().unwrap_or(Path::new("/")).components() {
        match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => resolved.push(name),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(BridgeError::invalid_config(
                    "installation source paths must be normalized",
                ));
            }
        }
        let metadata = fs::symlink_metadata(&resolved).map_err(BridgeError::io)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(BridgeError::invalid_config(
                "installation source ancestors must be real directories",
            ));
        }
        let trusted_tmp = resolved == Path::new("/tmp")
            && metadata.uid() == root_uid
            && metadata.mode() & 0o1000 != 0;
        let Some(next_private_boundary) = advance_private_source_boundary(
            metadata.uid(),
            metadata.mode(),
            current_uid,
            root_uid,
            below_private_user_ancestor,
            trusted_tmp,
        ) else {
            if !trusted_source_owner(metadata.uid(), current_uid, root_uid) {
                return Err(BridgeError::invalid_config(
                    "installation source ancestors must be owned by root or the current user",
                ));
            }
            return Err(BridgeError::invalid_config(
                "installation source ancestors must not be writable by group or other users unless sealed below a private current-user ancestor",
            ));
        };
        below_private_user_ancestor = next_private_boundary;
    }
    Ok(())
}

fn advance_private_source_boundary(
    owner_uid: u32,
    mode: u32,
    current_uid: u32,
    root_uid: u32,
    below_private_user_ancestor: bool,
    trusted_tmp: bool,
) -> Option<bool> {
    if !trusted_source_owner(owner_uid, current_uid, root_uid) {
        return None;
    }
    let writable_by_group_or_other = mode & 0o022 != 0;
    if writable_by_group_or_other
        && !trusted_tmp
        && !(below_private_user_ancestor && owner_uid == current_uid)
    {
        return None;
    }
    Some(below_private_user_ancestor || (owner_uid == current_uid && mode & 0o077 == 0))
}

fn validate_trusted_source_directory(metadata: &fs::Metadata) -> BridgeResult<()> {
    // SAFETY: geteuid has no preconditions and retains no pointers.
    let uid = unsafe { libc::geteuid() };
    let root_uid = fs::symlink_metadata("/").map_err(BridgeError::io)?.uid();
    if !metadata.is_dir()
        || !trusted_source_owner(metadata.uid(), uid, root_uid)
        || metadata.mode() & 0o022 != 0
    {
        return Err(BridgeError::invalid_config(
            "Skill directories must be root/current-user-owned and not group/other writable",
        ));
    }
    Ok(())
}

fn hash_secure_skill_tree(root: &Path) -> BridgeResult<String> {
    fn visit(root: &Path, directory: &Path, hasher: &mut Sha256) -> BridgeResult<()> {
        validate_trusted_source_directory(
            &fs::symlink_metadata(directory).map_err(BridgeError::io)?,
        )?;
        let mut entries = fs::read_dir(directory)
            .map_err(BridgeError::io)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(BridgeError::io)?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(BridgeError::io)?;
            let relative = path
                .strip_prefix(root)
                .map_err(|_| BridgeError::invalid_config("Skill tree escaped its root"))?;
            let relative = relative.as_os_str().as_bytes();
            hasher.update((relative.len() as u64).to_be_bytes());
            hasher.update(relative);
            if metadata.is_dir() {
                hasher.update(b"D");
                visit(root, &path, hasher)?;
            } else if metadata.is_file() {
                validate_trusted_source_file(&metadata, false)?;
                hasher.update(b"F");
                hasher.update(metadata.len().to_be_bytes());
                let mut file = fs::File::open(&path).map_err(BridgeError::io)?;
                let mut buffer = [0u8; 64 * 1024];
                loop {
                    let count = file.read(&mut buffer).map_err(BridgeError::io)?;
                    if count == 0 {
                        break;
                    }
                    hasher.update(&buffer[..count]);
                }
            } else {
                return Err(BridgeError::invalid_config(
                    "Skill tree may contain only real directories and regular files",
                ));
            }
        }
        Ok(())
    }

    let mut hasher = Sha256::new();
    hasher.update(b"codex-ssh-bridge-skill-tree-v1\0");
    visit(root, root, &mut hasher)?;
    Ok(hex_digest(&hasher.finalize()))
}

fn validate_trusted_source_file(metadata: &fs::Metadata, executable: bool) -> BridgeResult<()> {
    // SAFETY: geteuid has no preconditions and retains no pointers.
    let uid = unsafe { libc::geteuid() };
    let root_uid = fs::symlink_metadata("/").map_err(BridgeError::io)?.uid();
    if !metadata.is_file()
        || !trusted_source_owner(metadata.uid(), uid, root_uid)
        || metadata.mode() & 0o022 != 0
    {
        return Err(BridgeError::invalid_config(
            "installation sources must be regular, root/current-user-owned, and not group/other writable",
        ));
    }
    if executable && metadata.mode() & 0o111 == 0 {
        return Err(BridgeError::invalid_config(
            "installation executable is not executable",
        ));
    }
    Ok(())
}

fn trusted_source_owner(file_uid: u32, effective_uid: u32, root_uid: u32) -> bool {
    file_uid == 0 || file_uid == effective_uid || file_uid == root_uid
}

fn validate_private_identity_file(metadata: &fs::Metadata) -> BridgeResult<()> {
    // SAFETY: geteuid has no preconditions and retains no pointers.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
        return Err(BridgeError::invalid_config(
            "installation identity must be a private current-user-owned regular file",
        ));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> BridgeResult<String> {
    let mut file = fs::File::open(path).map_err(BridgeError::io)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(BridgeError::io)?;
        if count == 0 {
            return Ok(hex_digest(&hasher.finalize()));
        }
        hasher.update(&buffer[..count]);
    }
}

fn read_bounded(path: &Path, maximum: u64) -> BridgeResult<Vec<u8>> {
    let file = fs::File::open(path).map_err(BridgeError::io)?;
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(BridgeError::io)?;
    if bytes.len() as u64 > maximum {
        return Err(BridgeError::invalid_config(
            "installation identity exceeds its size limit",
        ));
    }
    Ok(bytes)
}

fn path_string(path: &Path) -> BridgeResult<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| BridgeError::invalid_config("installation paths must be valid UTF-8"))
}

fn hex_digest(digest: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn report(applied: bool, resolved: &ResolvedInstall, actions: Vec<String>) -> InstallReport {
    InstallReport {
        applied,
        installation_id: resolved.identity.installation_id.clone(),
        actions,
    }
}

fn find_executable(name: &str) -> BridgeResult<PathBuf> {
    let path = nonempty_environment("PATH")
        .ok_or_else(|| BridgeError::invalid_config("PATH is required to locate Codex"))?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(name);
        if let Ok(canonical) = canonical_secure_codex_executable(&candidate) {
            return Ok(canonical);
        }
    }
    Err(BridgeError::invalid_config("codex was not found on PATH"))
}

fn nonempty_environment(name: &str) -> Option<OsString> {
    std::env::var_os(name).filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::advance_private_source_boundary;

    #[test]
    fn private_source_boundary_never_trusts_foreign_or_writable_root_owned_descendants() {
        let current_uid = 1000;
        let root_uid = 65534;

        assert_eq!(
            advance_private_source_boundary(2000, 0o700, current_uid, root_uid, true, false),
            None
        );
        assert_eq!(
            advance_private_source_boundary(root_uid, 0o775, current_uid, root_uid, true, false),
            None
        );
        assert_eq!(
            advance_private_source_boundary(root_uid, 0o755, current_uid, root_uid, true, false),
            Some(true)
        );
    }

    #[test]
    fn sticky_tmp_does_not_establish_a_private_user_boundary() {
        assert_eq!(
            advance_private_source_boundary(0, 0o1777, 1000, 0, false, true),
            Some(false)
        );
    }
}
