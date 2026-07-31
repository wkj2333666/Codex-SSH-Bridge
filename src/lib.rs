pub mod capability;
pub mod cli;
pub mod config;
pub mod error;
pub mod job_protocol;
pub mod mcp;
pub mod output;
pub mod path;
pub mod profile;
pub mod quote;
pub mod remote;
pub mod remote_helper;
pub mod remote_helper_protocol;
pub mod remote_job_runner;
pub mod ssh;

pub use error::{BridgeError, BridgeResult, ErrorCode, ErrorDetails};

pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_READ_BYTES: usize = 1024 * 1024;
pub const MAX_WRITE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;

// Remote MCP operations use absolute paths.  The slash is the transport
// working root used to safely bind those paths for the persistent dispatcher;
// it is not a user-configurable workspace or an authorization boundary.
pub(crate) const REMOTE_OPERATION_ROOT: &str = "/";
