use std::io::Cursor;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use image::{DynamicImage, ImageDecoder, ImageFormat, ImageReader, Limits};
use serde::Deserialize;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::error::{BridgeError, BridgeResult, ErrorCode};
use crate::output::{InternalSpoolOwner, StreamKind};
use crate::ssh::{FixedOperationKind, FixedRunRequest, RootedPathInputs};

use super::protocol::read_small_stream;
use super::{RemoteBridge, StatRequest, attach_fixed_result_context, resolve_stat};

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ImageDetail {
    #[default]
    High,
    Original,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewImageRequest {
    pub host: String,
    pub path: String,
    #[serde(default)]
    pub detail: ImageDetail,
}

pub struct ViewedImage {
    pub bytes: Vec<u8>,
    pub mime_type: &'static str,
    pub original_width: u32,
    pub original_height: u32,
    pub width: u32,
    pub height: u32,
}

// One bounded binary read over the existing dispatcher; no remote Python,
// base64 process, per-chunk RPC, or separately authenticated file server.
const IMAGE_SCRIPT: &str = r#"
path=$1
budget=$2
if [ ! -e "$path" ]; then printf 'NOT_FOUND' >&2; exit 0; fi
if [ ! -f "$path" ]; then printf 'INVALID_ARGUMENT' >&2; exit 0; fi
if [ ! -r "$path" ]; then printf 'PERMISSION_DENIED' >&2; exit 0; fi
size=$(stat --printf='%s' -- "$path" 2>/dev/null) || { printf 'PERMISSION_DENIED' >&2; exit 0; }
if [ "$size" -gt "$budget" ]; then printf 'OUTPUT_LIMIT' >&2; exit 0; fi
head -c "$((budget + 1))" -- "$path" || exit 1
printf 'OK' >&2
"#;

impl RemoteBridge {
    pub async fn view_image(
        &self,
        request: ViewImageRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<ViewedImage> {
        let resolved = resolve_stat(
            self.runner.config(),
            StatRequest {
                host: request.host,
                paths: vec![request.path],
            },
        )?;
        self.edit_barrier(&resolved.host, cancel.clone()).await?;
        let limits = self.runner.config().limits();
        let limit = limits.max_read_bytes;
        let owner = InternalSpoolOwner::new();
        let result = self
            .execute_readonly_fixed(
                FixedRunRequest {
                    kind: FixedOperationKind::ReadOnly,
                    host: resolved.host.clone(),
                    script: IMAGE_SCRIPT,
                    args: vec![resolved.paths[0].as_str().to_owned(), limit.to_string()],
                    stdin: None,
                    rooted_paths: RootedPathInputs {
                        argument_indices: &[0],
                        argument_stride: None,
                        stdin_nul_paths: false,
                    },
                    required_capabilities: &["read_slice", "stat_printf"],
                    stdout_limit: limit as u64 + 1,
                    stderr_limit: 1024,
                    timeout: Duration::from_millis(limits.command_timeout_ms),
                    cleanup: owner.registration(),
                },
                cancel.clone(),
            )
            .await?;
        let attach = |error| attach_fixed_result_context(error, &resolved.host, &result);
        let status = read_small_stream(&result.output, StreamKind::Stderr, 1024)
            .await
            .map_err(&attach)?;
        if status != b"OK" {
            let (code, message) = match status.as_slice() {
                b"NOT_FOUND" => (ErrorCode::NotFound, "remote image was not found"),
                b"PERMISSION_DENIED" => {
                    (ErrorCode::PermissionDenied, "remote image is not readable")
                }
                b"INVALID_ARGUMENT" => (
                    ErrorCode::InvalidArgument,
                    "remote image must be a regular file",
                ),
                b"OUTPUT_LIMIT" => (
                    ErrorCode::OutputLimit,
                    "remote image exceeds the configured max_read_bytes limit; create a smaller preview",
                ),
                _ => (ErrorCode::RemoteExit, "remote image read failed"),
            };
            return Err(attach(BridgeError::new(code, message, false)));
        }
        let bytes = read_small_stream(&result.output, StreamKind::Stdout, limit + 1)
            .await
            .map_err(&attach)?;
        if bytes.len() > limit {
            return Err(attach(BridgeError::new(
                ErrorCode::OutputLimit,
                "remote image grew beyond the read limit",
                false,
            )));
        }
        // Decoding is CPU work: keep it off the MCP async executor. Work is
        // bounded by encoded bytes, dimensions, pixels and decoder allocations.
        static DECODERS: OnceLock<Arc<Semaphore>> = OnceLock::new();
        let decoders = DECODERS.get_or_init(|| Arc::new(Semaphore::new(2)));
        let permit = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(attach(BridgeError::new(ErrorCode::Cancelled, "image request cancelled", false))),
            permit = Arc::clone(decoders).acquire_owned() => permit.map_err(|_| attach(BridgeError::new(ErrorCode::Io, "image decoder unavailable", false)))?,
        };
        let decode = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            prepare_image(bytes, request.detail)
        });
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(attach(BridgeError::new(ErrorCode::Cancelled, "image request cancelled", false))),
            decoded = decode => decoded.map_err(|_| attach(BridgeError::new(ErrorCode::Io, "image decoder failed", false)))?.map_err(attach),
        }
    }
}

fn invalid_image() -> BridgeError {
    BridgeError::invalid_argument("unsupported or corrupt image; provide a valid PNG or JPEG")
}

fn prepare_image(bytes: Vec<u8>, detail: ImageDetail) -> BridgeResult<ViewedImage> {
    let format = image::guess_format(&bytes).map_err(|_| invalid_image())?;
    if !matches!(format, ImageFormat::Png | ImageFormat::Jpeg) {
        return Err(invalid_image());
    }
    let mut reader = ImageReader::with_format(Cursor::new(&bytes), format);
    let mut limits = Limits::default();
    limits.max_image_width = Some(16_384);
    limits.max_image_height = Some(16_384);
    limits.max_alloc = Some(128 * 1024 * 1024);
    reader.limits(limits);
    let mut decoder = reader.into_decoder().map_err(|_| invalid_image())?;
    let (width, height) = decoder.dimensions();
    if width == 0 || height == 0 || u64::from(width) * u64::from(height) > 16_000_000 {
        return Err(BridgeError::new(
            ErrorCode::OutputLimit,
            "image exceeds the 16 megapixel decoding limit",
            false,
        ));
    }
    let orientation = decoder.orientation().map_err(|_| invalid_image())?;
    let mut decoded = DynamicImage::from_decoder(decoder).map_err(|_| invalid_image())?;
    decoded.apply_orientation(orientation);
    let original_width = decoded.width();
    let original_height = decoded.height();
    if detail == ImageDetail::High && (original_width > 1536 || original_height > 1536) {
        decoded = decoded.thumbnail(1536, 1536);
    }
    let width = decoded.width();
    let height = decoded.height();
    let (bytes, mime_type) = if width == original_width
        && height == original_height
        && orientation == image::metadata::Orientation::NoTransforms
    {
        (
            bytes,
            if format == ImageFormat::Png {
                "image/png"
            } else {
                "image/jpeg"
            },
        )
    } else {
        let mut encoded = Cursor::new(Vec::new());
        // Preserve transparency and avoid introducing lossy artifacts into diagrams.
        let output_format = if format == ImageFormat::Png {
            ImageFormat::Png
        } else {
            ImageFormat::Jpeg
        };
        decoded
            .write_to(&mut encoded, output_format)
            .map_err(|_| invalid_image())?;
        (
            encoded.into_inner(),
            if output_format == ImageFormat::Png {
                "image/png"
            } else {
                "image/jpeg"
            },
        )
    };
    Ok(ViewedImage {
        bytes,
        mime_type,
        original_width,
        original_height,
        width,
        height,
    })
}
