use std::path::PathBuf;

use serde::Serialize;

use crate::error::{BridgeError, BridgeResult};

#[derive(Debug, Clone)]
pub struct InstallLayout {
    pub binary: PathBuf,
}

impl InstallLayout {
    pub fn discover() -> BridgeResult<Self> {
        Ok(Self {
            binary: std::env::current_exe().map_err(BridgeError::io)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallReport {
    pub applied: bool,
    pub installation_id: String,
    pub actions: Vec<String>,
}

fn unsupported() -> BridgeError {
    BridgeError::invalid_config(
        "automatic installation is not yet supported on Windows; register bin\\codex-ssh-bridge.exe mcp with Codex",
    )
}

pub async fn install_user(_layout: InstallLayout, _apply: bool) -> BridgeResult<InstallReport> {
    Err(unsupported())
}

pub async fn install_packaged_user(
    _layout: InstallLayout,
    _apply: bool,
) -> BridgeResult<InstallReport> {
    Err(unsupported())
}

pub async fn uninstall_user(_layout: InstallLayout, _apply: bool) -> BridgeResult<InstallReport> {
    Err(unsupported())
}
