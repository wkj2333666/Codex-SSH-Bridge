use std::io::{self, Write};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use image::{DynamicImage, ImageDecoder, ImageEncoder, ImageFormat, ImageReader, Limits};
use serde::Deserialize;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::error::{BridgeError, BridgeResult, ErrorCode};
use crate::output::{InternalCapturedOutput, InternalSpoolOwner, StreamKind};
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
        response_bytes: usize,
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
        // Source bytes use the existing streaming output/disk quota, not the
        // text read limit or MCP response frame. Reserve stderr and a growth sentinel.
        let limit = limits.max_output_bytes.saturating_sub(1025);
        if limit == 0 || response_bytes == 0 {
            return Err(image_output_limit());
        }
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
                    stdout_limit: limit + 1,
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
                    "remote image exceeds the configured streaming output/spool budget",
                ),
                _ => (ErrorCode::RemoteExit, "remote image read failed"),
            };
            return Err(attach(BridgeError::new(code, message, false)));
        }
        if result.output.stdout_len > limit {
            return Err(attach(BridgeError::new(
                ErrorCode::OutputLimit,
                "remote image grew beyond the streaming output/spool budget",
                false,
            )));
        }
        // Decoding is CPU work: keep it off the MCP async executor. Work is
        // bounded by dimensions, pixels and decoder allocations. Source bytes
        // stay in the captured file, including while waiting for a decoder.
        static DECODERS: OnceLock<Arc<Semaphore>> = OnceLock::new();
        let decoders = DECODERS.get_or_init(|| Arc::new(Semaphore::new(2)));
        let permit = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(attach(BridgeError::new(ErrorCode::Cancelled, "image request cancelled", false))),
            permit = Arc::clone(decoders).acquire_owned() => permit.map_err(|_| attach(BridgeError::new(ErrorCode::Io, "image decoder unavailable", false)))?,
        };
        let output = result.output.clone();
        let decode_cancel = cancel.clone();
        let decode = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            // Cancellation drops the async future, not spawn_blocking. Keep
            // both disk quota accounting and cleanup alive through actual decode.
            let _owner = owner;
            prepare_image(output, request.detail, response_bytes, &decode_cancel)
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

fn image_output_limit() -> BridgeError {
    BridgeError::new(
        ErrorCode::OutputLimit,
        "image cannot fit the configured output budget; use detail high or a smaller preview",
        false,
    )
}

fn check_cancel(cancel: &CancellationToken) -> BridgeResult<()> {
    if cancel.is_cancelled() {
        return Err(BridgeError::new(
            ErrorCode::Cancelled,
            "image request cancelled",
            false,
        ));
    }
    Ok(())
}

fn prepare_image(
    output: InternalCapturedOutput,
    detail: ImageDetail,
    response_bytes: usize,
    cancel: &CancellationToken,
) -> BridgeResult<ViewedImage> {
    check_cancel(cancel)?;
    let mut reader = ImageReader::new(output.open_reader(StreamKind::Stdout)?)
        .with_guessed_format()
        .map_err(|_| invalid_image())?;
    let format = reader.format().ok_or_else(invalid_image)?;
    if !matches!(format, ImageFormat::Png | ImageFormat::Jpeg) {
        return Err(invalid_image());
    }
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
    check_cancel(cancel)?;
    decoded.apply_orientation(orientation);
    let original_width = decoded.width();
    let original_height = decoded.height();
    if detail == ImageDetail::High && (original_width > 1536 || original_height > 1536) {
        decoded = decoded.thumbnail(1536, 1536);
    }
    // Always encode pixels, not the source container (which may have large
    // metadata). Bound the encoder's output before allocating the MCP payload.
    let bytes = loop {
        check_cancel(cancel)?;
        let mut encoded = BoundedImageWriter {
            bytes: Vec::new(),
            limit: response_bytes,
            exceeded: false,
        };
        let result = if format == ImageFormat::Png {
            image::codecs::png::PngEncoder::new(&mut encoded).write_image(
                decoded.as_bytes(),
                decoded.width(),
                decoded.height(),
                decoded.color().into(),
            )
        } else {
            image::codecs::jpeg::JpegEncoder::new(&mut encoded).encode_image(&decoded)
        };
        check_cancel(cancel)?;
        if result.is_ok() {
            break encoded.bytes;
        }
        if !encoded.exceeded {
            return Err(invalid_image());
        }
        if detail == ImageDetail::Original || (decoded.width() == 1 && decoded.height() == 1) {
            return Err(image_output_limit());
        }
        // Preserve PNG alpha; reduce preview dimensions instead of converting
        // transparent images to JPEG. Original never silently loses dimensions.
        decoded = decoded.thumbnail(
            (decoded.width() * 3 / 4).max(1),
            (decoded.height() * 3 / 4).max(1),
        );
    };
    let width = decoded.width();
    let height = decoded.height();
    let mime_type = if format == ImageFormat::Png {
        "image/png"
    } else {
        "image/jpeg"
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

struct BoundedImageWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl Write for BoundedImageWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::other("image response budget exceeded"));
        }
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
