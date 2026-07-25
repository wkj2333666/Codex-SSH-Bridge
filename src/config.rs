#![allow(
    clippy::result_large_err,
    reason = "Task 1 requires BridgeResult<T> = Result<T, BridgeError> with inline ErrorDetails"
)]

use std::collections::{BTreeMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::error::{BridgeError, BridgeResult};
use crate::{MAX_FRAME_BYTES, MAX_OUTPUT_BYTES, MAX_READ_BYTES, MAX_WRITE_BYTES};

const MAX_CONNECT_TIMEOUT_MS: u64 = 120_000;
const MAX_COMMAND_TIMEOUT_MS: u64 = 3_600_000;
const MAX_READ_CHUNK_BYTES: usize = 1024 * 1024;
const MAX_PREVIEW_BYTES: usize = 1024 * 1024;
pub const CONFIG_VERSION: u32 = 2;
pub const MAX_REMOTE_CONTEXT_ROOT_BYTES: usize = 65_536;
pub const DEFAULT_GLOBAL_SPOOL_QUOTA_BYTES: u64 = 512 * 1024 * 1024;
pub const MIN_GLOBAL_SPOOL_QUOTA_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_GLOBAL_SPOOL_QUOTA_BYTES: u64 = 512 * 1024 * 1024;
pub const DEFAULT_RETENTION_SERIALIZATION_JOBS: usize = 2;
pub const MAX_RETENTION_SERIALIZATION_JOBS: usize = 4;
pub const MAX_SPOOL_ENTRIES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub limits: Limits,
    #[serde(skip)]
    pub hosts: BTreeMap<String, HostProfile>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            limits: Limits::default(),
            hosts: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub connect_timeout_ms: u64,
    pub command_timeout_ms: u64,
    pub max_frame_bytes: usize,
    pub read_chunk_bytes: usize,
    pub max_read_bytes: usize,
    pub max_write_bytes: usize,
    pub preview_bytes: usize,
    pub max_output_bytes: u64,
    pub global_spool_quota_bytes: u64,
    pub retention_serialization_jobs: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 10_000,
            command_timeout_ms: 300_000,
            max_frame_bytes: MAX_FRAME_BYTES,
            read_chunk_bytes: 256 * 1024,
            max_read_bytes: MAX_READ_BYTES,
            max_write_bytes: MAX_WRITE_BYTES,
            preview_bytes: 256 * 1024,
            max_output_bytes: MAX_OUTPUT_BYTES,
            global_spool_quota_bytes: DEFAULT_GLOBAL_SPOOL_QUOTA_BYTES,
            retention_serialization_jobs: DEFAULT_RETENTION_SERIALIZATION_JOBS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostProfile {
    pub root: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub limits: HostLimitOverrides,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HostLimitOverrides {
    pub connect_timeout_ms: Option<u64>,
    pub command_timeout_ms: Option<u64>,
    pub max_read_bytes: Option<usize>,
    pub max_write_bytes: Option<usize>,
    pub preview_bytes: Option<usize>,
    pub max_output_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveLimits {
    pub connect_timeout_ms: u64,
    pub command_timeout_ms: u64,
    pub max_frame_bytes: usize,
    pub read_chunk_bytes: usize,
    pub max_read_bytes: usize,
    pub max_write_bytes: usize,
    pub preview_bytes: usize,
    pub max_output_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedConfig {
    pub config: Config,
    pub source: ConfigSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigratedV1 {
    pub config: Config,
    pub explicit_aliases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredHost {
    pub alias: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigSource {
    pub path: PathBuf,
    pub from_environment: bool,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct ResolvedHost<'a> {
    pub alias: &'a str,
    pub profile: &'a HostProfile,
    pub limits: EffectiveLimits,
}

impl Config {
    pub fn default_path() -> BridgeResult<PathBuf> {
        default_config_path()
    }

    pub fn load(path: &Path) -> BridgeResult<Self> {
        validate_secure_existing_ancestors(path)?;
        let mut file = open_config(path)?;
        validate_file_security(&file)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(BridgeError::io)?;
        let config: Self = toml::from_str(&contents).map_err(|error| {
            BridgeError::invalid_config(format!("invalid configuration: {error}"))
        })?;
        config.validate()?;
        Ok(config)
    }

    pub fn load_default() -> BridgeResult<LoadedConfig> {
        let (path, from_environment, warning) = match std::env::var_os("CODEX_SSH_BRIDGE_CONFIG") {
            Some(path) => (
                PathBuf::from(path),
                true,
                Some(
                    "CODEX_SSH_BRIDGE_CONFIG is trusted execution-authority input; verify its source and permissions"
                        .to_owned(),
                ),
            ),
            None => (default_config_path()?, false, None),
        };
        let mut config = Self::load(&path)?;
        config.merge_ssh_aliases();
        Ok(LoadedConfig {
            config,
            source: ConfigSource {
                path,
                from_environment,
                warning,
            },
        })
    }

    /// Load a config file and add aliases discovered in the user's OpenSSH
    /// config without overwriting explicit bridge profiles.
    pub fn load_with_discovery(path: &Path) -> BridgeResult<Self> {
        let mut config = Self::load(path)?;
        config.merge_ssh_aliases();
        Ok(config)
    }

    pub fn load_with_discovery_from(path: &Path, ssh_config: &Path) -> BridgeResult<Self> {
        let mut config = Self::load(path)?;
        config.merge_ssh_aliases_from(ssh_config);
        Ok(config)
    }

    fn merge_ssh_aliases(&mut self) {
        let Some(home) = nonempty_environment("HOME") else {
            return;
        };
        self.merge_ssh_aliases_from(&PathBuf::from(home).join(".ssh/config"));
    }

    fn merge_ssh_aliases_from(&mut self, ssh_config: &Path) {
        for alias in discover_ssh_aliases_from(ssh_config) {
            self.hosts.entry(alias).or_insert_with(|| HostProfile {
                root: "/".to_owned(),
                description: None,
                read_only: false,
                limits: HostLimitOverrides::default(),
            });
        }
    }

    pub fn save_atomic(&self, path: &Path) -> BridgeResult<()> {
        self.validate()?;
        validate_secure_existing_ancestors(path)?;
        match fs::symlink_metadata(path) {
            Ok(_) => validate_file_security(&open_config(path)?)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(BridgeError::io(error)),
        }
        let serialized = toml::to_string_pretty(self).map_err(|error| {
            BridgeError::invalid_config(format!("cannot serialize configuration: {error}"))
        })?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut temporary = NamedTempFile::new_in(parent).map_err(BridgeError::io)?;
        set_private_permissions(temporary.as_file())?;
        temporary
            .write_all(serialized.as_bytes())
            .map_err(BridgeError::io)?;
        temporary.flush().map_err(BridgeError::io)?;
        temporary.as_file().sync_all().map_err(BridgeError::io)?;
        temporary
            .persist(path)
            .map_err(|error| BridgeError::io(error.error))?;
        Ok(())
    }

    pub fn host<'a>(&'a self, alias: &'a str) -> BridgeResult<ResolvedHost<'a>> {
        if !valid_alias(alias) {
            return Err(BridgeError::invalid_argument("invalid host alias"));
        }
        self.validate()?;
        let profile = self
            .hosts
            .get(alias)
            .ok_or_else(|| BridgeError::invalid_config("unknown host alias"))?;
        Ok(ResolvedHost {
            alias,
            profile,
            limits: effective_limits(&self.limits, &profile.limits),
        })
    }

    pub fn limits(&self) -> EffectiveLimits {
        effective_limits(&self.limits, &HostLimitOverrides::default())
    }

    pub fn discover_hosts(&self) -> Vec<DiscoveredHost> {
        self.hosts
            .keys()
            .map(|alias| DiscoveredHost {
                alias: alias.clone(),
            })
            .collect()
    }

    pub fn require_discovered_alias(&self, alias: &str) -> BridgeResult<DiscoveredHost> {
        if !valid_alias(alias) {
            return Err(BridgeError::invalid_argument("invalid host alias"));
        }
        if !self.hosts.contains_key(alias) {
            return Err(BridgeError::invalid_config("unknown host alias"));
        }
        Ok(DiscoveredHost {
            alias: alias.to_owned(),
        })
    }

    fn validate(&self) -> BridgeResult<()> {
        if self.version != CONFIG_VERSION {
            return Err(BridgeError::invalid_config(format!(
                "unsupported configuration version {}; expected {CONFIG_VERSION}",
                self.version
            )));
        }
        validate_limits(&self.limits)?;
        for alias in self.hosts.keys() {
            if !valid_alias(alias) {
                return Err(BridgeError::invalid_config(format!(
                    "invalid host alias: {alias}"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ConfigV1 {
    version: u32,
    limits: LimitsV1,
    hosts: BTreeMap<String, HostProfile>,
}

impl Default for ConfigV1 {
    fn default() -> Self {
        Self {
            version: 1,
            limits: LimitsV1::default(),
            hosts: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct LimitsV1 {
    connect_timeout_ms: u64,
    command_timeout_ms: u64,
    max_frame_bytes: usize,
    read_chunk_bytes: usize,
    max_read_bytes: usize,
    max_write_bytes: usize,
    preview_bytes: usize,
    max_output_bytes: u64,
    #[serde(rename = "global_concurrency")]
    _global_concurrency: usize,
    #[serde(rename = "per_host_concurrency")]
    _per_host_concurrency: usize,
    global_spool_quota_bytes: u64,
    retention_serialization_jobs: usize,
}

impl Default for LimitsV1 {
    fn default() -> Self {
        let current = Limits::default();
        Self {
            connect_timeout_ms: current.connect_timeout_ms,
            command_timeout_ms: current.command_timeout_ms,
            max_frame_bytes: current.max_frame_bytes,
            read_chunk_bytes: current.read_chunk_bytes,
            max_read_bytes: current.max_read_bytes,
            max_write_bytes: current.max_write_bytes,
            preview_bytes: current.preview_bytes,
            max_output_bytes: current.max_output_bytes,
            _global_concurrency: 8,
            _per_host_concurrency: 2,
            global_spool_quota_bytes: current.global_spool_quota_bytes,
            retention_serialization_jobs: current.retention_serialization_jobs,
        }
    }
}

pub fn migrate_v1_text(contents: &str) -> BridgeResult<MigratedV1> {
    let old: ConfigV1 = toml::from_str(contents)
        .map_err(|error| BridgeError::invalid_config(format!("invalid configuration: {error}")))?;
    if old.version != 1 {
        return Err(BridgeError::invalid_config(
            "configuration is not version 1",
        ));
    }
    let explicit_aliases = old.hosts.keys().cloned().collect::<Vec<_>>();
    let config = Config {
        version: CONFIG_VERSION,
        limits: Limits {
            connect_timeout_ms: old.limits.connect_timeout_ms,
            command_timeout_ms: old.limits.command_timeout_ms,
            max_frame_bytes: old.limits.max_frame_bytes,
            read_chunk_bytes: old.limits.read_chunk_bytes,
            max_read_bytes: old.limits.max_read_bytes,
            max_write_bytes: old.limits.max_write_bytes,
            preview_bytes: old.limits.preview_bytes,
            max_output_bytes: old.limits.max_output_bytes,
            global_spool_quota_bytes: old.limits.global_spool_quota_bytes,
            retention_serialization_jobs: old.limits.retention_serialization_jobs,
        },
        hosts: BTreeMap::new(),
    };
    config.validate()?;
    Ok(MigratedV1 {
        config,
        explicit_aliases,
    })
}

pub fn migrate_v1_file(path: &Path) -> BridgeResult<MigratedV1> {
    validate_secure_existing_ancestors(path)?;
    let mut file = open_config(path)?;
    validate_file_security(&file)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(BridgeError::io)?;
    migrate_v1_text(&contents)
}

fn validate_limits(limits: &Limits) -> BridgeResult<()> {
    validate_u64(
        "connect_timeout_ms",
        limits.connect_timeout_ms,
        MAX_CONNECT_TIMEOUT_MS,
    )?;
    validate_u64(
        "command_timeout_ms",
        limits.command_timeout_ms,
        MAX_COMMAND_TIMEOUT_MS,
    )?;
    validate_usize("max_frame_bytes", limits.max_frame_bytes, MAX_FRAME_BYTES)?;
    validate_usize(
        "read_chunk_bytes",
        limits.read_chunk_bytes,
        MAX_READ_CHUNK_BYTES,
    )?;
    validate_usize("max_read_bytes", limits.max_read_bytes, MAX_READ_BYTES)?;
    validate_usize("max_write_bytes", limits.max_write_bytes, MAX_WRITE_BYTES)?;
    validate_usize("preview_bytes", limits.preview_bytes, MAX_PREVIEW_BYTES)?;
    validate_u64(
        "max_output_bytes",
        limits.max_output_bytes,
        MAX_OUTPUT_BYTES,
    )?;
    if !(MIN_GLOBAL_SPOOL_QUOTA_BYTES..=MAX_GLOBAL_SPOOL_QUOTA_BYTES)
        .contains(&limits.global_spool_quota_bytes)
    {
        return Err(BridgeError::invalid_config(format!(
            "global_spool_quota_bytes must be between {MIN_GLOBAL_SPOOL_QUOTA_BYTES} and {MAX_GLOBAL_SPOOL_QUOTA_BYTES}"
        )));
    }
    validate_usize(
        "retention_serialization_jobs",
        limits.retention_serialization_jobs,
        MAX_RETENTION_SERIALIZATION_JOBS,
    )?;
    Ok(())
}

fn validate_u64(name: &str, value: u64, maximum: u64) -> BridgeResult<()> {
    if value == 0 || value > maximum {
        return Err(BridgeError::invalid_config(format!(
            "{name} must be between 1 and {maximum}"
        )));
    }
    Ok(())
}

fn validate_usize(name: &str, value: usize, maximum: usize) -> BridgeResult<()> {
    if value == 0 || value > maximum {
        return Err(BridgeError::invalid_config(format!(
            "{name} must be between 1 and {maximum}"
        )));
    }
    Ok(())
}

fn effective_limits(global: &Limits, host: &HostLimitOverrides) -> EffectiveLimits {
    EffectiveLimits {
        connect_timeout_ms: host.connect_timeout_ms.unwrap_or(global.connect_timeout_ms),
        command_timeout_ms: host.command_timeout_ms.unwrap_or(global.command_timeout_ms),
        max_frame_bytes: global.max_frame_bytes,
        read_chunk_bytes: global.read_chunk_bytes,
        max_read_bytes: host.max_read_bytes.unwrap_or(global.max_read_bytes),
        max_write_bytes: host.max_write_bytes.unwrap_or(global.max_write_bytes),
        preview_bytes: host.preview_bytes.unwrap_or(global.preview_bytes),
        max_output_bytes: host.max_output_bytes.unwrap_or(global.max_output_bytes),
    }
}

fn valid_alias(alias: &str) -> bool {
    let bytes = alias.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

pub fn discover_ssh_aliases_from(path: &Path) -> Vec<String> {
    let mut aliases = BTreeMap::new();
    let mut visited = HashSet::new();
    collect_ssh_aliases(path, &mut visited, &mut aliases, 0);
    aliases.into_keys().collect()
}

fn collect_ssh_aliases(
    path: &Path,
    visited: &mut HashSet<PathBuf>,
    aliases: &mut BTreeMap<String, ()>,
    depth: usize,
) {
    const MAX_INCLUDE_DEPTH: usize = 8;
    if depth > MAX_INCLUDE_DEPTH {
        return;
    }
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_owned());
    if !visited.insert(canonical) {
        return;
    }
    let Ok(contents) = fs::read_to_string(path) else {
        return;
    };
    for line in contents.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        let mut fields = line.split_whitespace();
        let Some(keyword) = fields.next() else {
            continue;
        };
        if keyword.eq_ignore_ascii_case("host") {
            for candidate in fields {
                if candidate.starts_with('!')
                    || candidate
                        .bytes()
                        .any(|byte| matches!(byte, b'*' | b'?' | b'['))
                    || !valid_alias(candidate)
                {
                    continue;
                }
                aliases.insert(candidate.to_owned(), ());
            }
        } else if keyword.eq_ignore_ascii_case("include") {
            for pattern in fields {
                for included in expand_ssh_include(path, pattern) {
                    collect_ssh_aliases(&included, visited, aliases, depth + 1);
                }
            }
        }
    }
}

fn expand_ssh_include(source: &Path, pattern: &str) -> Vec<PathBuf> {
    let pattern = pattern
        .strip_prefix("~/")
        .and_then(|suffix| {
            nonempty_environment("HOME").map(|home| PathBuf::from(home).join(suffix))
        })
        .unwrap_or_else(|| {
            let path = PathBuf::from(pattern);
            if path.is_absolute() {
                path
            } else {
                source.parent().unwrap_or_else(|| Path::new(".")).join(path)
            }
        });
    let Some(file_name) = pattern.file_name().and_then(|name| name.to_str()) else {
        return Vec::new();
    };
    if !file_name
        .bytes()
        .any(|byte| matches!(byte, b'*' | b'?' | b'['))
    {
        return pattern.is_file().then_some(pattern).into_iter().collect();
    }
    let Some(parent) = pattern.parent() else {
        return Vec::new();
    };
    let Ok(matcher) = globset::Glob::new(file_name).map(|glob| glob.compile_matcher()) else {
        return Vec::new();
    };
    let Ok(entries) = fs::read_dir(parent) else {
        return Vec::new();
    };
    let mut matches = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| matcher.is_match(name))
        })
        .collect::<Vec<_>>();
    matches.sort();
    matches
}

fn default_config_path() -> BridgeResult<PathBuf> {
    let base = nonempty_environment("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| nonempty_environment("HOME").map(|home| PathBuf::from(home).join(".config")))
        .ok_or_else(|| {
            BridgeError::invalid_config(
                "cannot determine config path: XDG_CONFIG_HOME and HOME are unset",
            )
        })?;
    Ok(base.join("codex-ssh-bridge").join("config.toml"))
}

fn nonempty_environment(name: &str) -> Option<OsString> {
    std::env::var_os(name).filter(|value| !value.is_empty())
}

fn open_config(path: &Path) -> BridgeResult<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }

    options.open(path).map_err(|error| {
        #[cfg(unix)]
        if error.raw_os_error() == Some(libc::ELOOP) {
            return BridgeError::invalid_config("configuration must not be a symlink");
        }
        BridgeError::io(error)
    })
}

pub(crate) fn validate_secure_existing_ancestors(path: &Path) -> BridgeResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::path::Component;

        if !path.is_absolute() {
            return Err(BridgeError::invalid_config(
                "configuration path must be absolute",
            ));
        }
        // SAFETY: credential getters have no preconditions and retain no pointers.
        let current_uid = unsafe { libc::geteuid() };
        let root_uid = fs::symlink_metadata("/").map_err(BridgeError::io)?.uid();
        let parent = path.parent().unwrap_or_else(|| Path::new("/"));
        let mut resolved = PathBuf::from("/");
        for component in parent.components() {
            match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(name) => resolved.push(name),
                Component::ParentDir | Component::Prefix(_) => {
                    return Err(BridgeError::invalid_config(
                        "configuration path must be normalized",
                    ));
                }
            }
            let metadata = match fs::symlink_metadata(&resolved) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => return Err(BridgeError::io(error)),
            };
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(BridgeError::invalid_config(
                    "configuration path ancestors must be real directories",
                ));
            }
            if metadata.uid() != root_uid && metadata.uid() != current_uid {
                return Err(BridgeError::invalid_config(
                    "configuration path ancestors must be owned by root or the current user",
                ));
            }
            let trusted_tmp = resolved == Path::new("/tmp")
                && metadata.uid() == root_uid
                && metadata.mode() & 0o1000 != 0;
            if metadata.mode() & 0o022 != 0 && !trusted_tmp {
                return Err(BridgeError::invalid_config(
                    "configuration path ancestors must not be writable by group or other users",
                ));
            }
        }
    }
    Ok(())
}

fn validate_file_security(file: &fs::File) -> BridgeResult<()> {
    let metadata = file.metadata().map_err(BridgeError::io)?;
    if !metadata.is_file() {
        return Err(BridgeError::invalid_config(
            "configuration must be a regular file",
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        // SAFETY: geteuid has no preconditions and does not dereference pointers.
        let current_uid = unsafe { libc::geteuid() };
        if metadata.uid() != current_uid {
            return Err(BridgeError::invalid_config(
                "configuration must be owned by the current user",
            ));
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(BridgeError::invalid_config(
                "configuration must not be writable by group or others",
            ));
        }
    }
    Ok(())
}

fn set_private_permissions(file: &fs::File) -> BridgeResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(BridgeError::io)?;
    }
    Ok(())
}
