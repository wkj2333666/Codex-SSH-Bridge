#![allow(
    clippy::result_large_err,
    reason = "remote path validation returns the shared BridgeResult shape"
)]

use crate::error::{BridgeError, BridgeResult, ErrorCode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemotePath {
    absolute: String,
    relative: String,
}

impl RemotePath {
    pub fn absolute(requested: &str) -> BridgeResult<Self> {
        if requested.as_bytes().contains(&0) {
            return Err(BridgeError::invalid_argument(
                "NUL is not valid in a remote path",
            ));
        }
        if !requested.starts_with('/') {
            return Err(BridgeError::new(
                ErrorCode::RemoteAbsolutePathRequired,
                "remote paths must be absolute",
                false,
            ));
        }
        Self::resolve("/", requested)
    }

    pub fn resolve(root: &str, requested: &str) -> BridgeResult<Self> {
        if root.as_bytes().contains(&0) || requested.as_bytes().contains(&0) {
            return Err(BridgeError::invalid_argument(
                "NUL is not valid in a remote path",
            ));
        }
        if !root.starts_with('/') {
            return Err(BridgeError::invalid_argument(
                "remote root must be an absolute path",
            ));
        }

        let root_components = normalize_absolute(root);
        let absolute_components = if requested.starts_with('/') {
            let components = normalize_absolute(requested);
            if !components.starts_with(&root_components) {
                return Err(outside_root());
            }
            components
        } else {
            normalize_relative(&root_components, requested)?
        };

        let relative = absolute_components[root_components.len()..].join("/");
        let absolute = if absolute_components.is_empty() {
            "/".to_owned()
        } else {
            format!("/{}", absolute_components.join("/"))
        };

        Ok(Self { absolute, relative })
    }

    pub fn as_str(&self) -> &str {
        &self.absolute
    }

    pub fn relative(&self) -> &str {
        &self.relative
    }
}

fn normalize_absolute(path: &str) -> Vec<String> {
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            value => components.push(value.to_owned()),
        }
    }
    components
}

fn normalize_relative(root: &[String], requested: &str) -> BridgeResult<Vec<String>> {
    let mut components = root.to_vec();
    for component in requested.split('/') {
        match component {
            "" | "." => {}
            ".." if components.len() == root.len() => return Err(outside_root()),
            ".." => {
                components.pop();
            }
            value => components.push(value.to_owned()),
        }
    }
    Ok(components)
}

fn outside_root() -> BridgeError {
    BridgeError::new(
        ErrorCode::PathOutsideRoot,
        "requested path is outside the configured root",
        false,
    )
}
