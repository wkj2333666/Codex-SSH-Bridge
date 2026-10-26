use std::io::{self, BufReader, Read, Write};
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
    let mut format = reader.format().ok_or_else(invalid_image)?;
    if !matches!(format, ImageFormat::Png | ImageFormat::Jpeg) {
        return Err(invalid_image());
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(16_384);
    limits.max_image_height = Some(16_384);
    limits.max_alloc = Some(128 * 1024 * 1024);
    reader.limits(limits);
    let (mut decoded, orientation) = if format == ImageFormat::Jpeg {
        // image 0.25's JPEG adapter calls read_to_end internally. Use a
        // reader-based decoder so encoded sources are not buffered wholesale.
        decode_jpeg(reader.into_inner(), cancel)?
    } else {
        let mut decoder = reader.into_decoder().map_err(|_| invalid_image())?;
        let (width, height) = decoder.dimensions();
        check_dimensions(width, height)?;
        let orientation = decoder.orientation().map_err(|_| invalid_image())?;
        (
            DynamicImage::from_decoder(decoder).map_err(|_| invalid_image())?,
            orientation,
        )
    };
    check_cancel(cancel)?;
    decoded.apply_orientation(orientation);
    let original_width = decoded.width();
    let original_height = decoded.height();
    if matches!(decoded, DynamicImage::ImageLuma16(_)) {
        // Preserve lossless 16-bit grayscale JPEG pixels in a PNG response.
        format = ImageFormat::Png;
    }
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

fn check_dimensions(width: u32, height: u32) -> BridgeResult<()> {
    if width == 0
        || height == 0
        || width > 16_384
        || height > 16_384
        || u64::from(width) * u64::from(height) > 16_000_000
    {
        return Err(BridgeError::new(
            ErrorCode::OutputLimit,
            "image exceeds the decoding dimension/pixel budget",
            false,
        ));
    }
    Ok(())
}

fn decode_jpeg(
    reader: impl Read,
    cancel: &CancellationToken,
) -> BridgeResult<(DynamicImage, image::metadata::Orientation)> {
    let mut decoder = jpeg_decoder::Decoder::new(BufReader::new(CancellableImageReader {
        inner: reader,
        cancel,
    }));
    decoder.set_max_decoding_buffer_size(128 * 1024 * 1024);
    decoder.read_info().map_err(|_| invalid_image())?;
    let info = decoder.info().ok_or_else(invalid_image)?;
    let (width, height) = (u32::from(info.width), u32::from(info.height));
    check_dimensions(width, height)?;
    let data = decoder.decode().map_err(|_| invalid_image())?;
    check_cancel(cancel)?;
    let orientation = decoder
        .exif_data()
        .and_then(image::metadata::Orientation::from_exif_chunk)
        .unwrap_or(image::metadata::Orientation::NoTransforms);
    let image = match info.pixel_format {
        jpeg_decoder::PixelFormat::RGB24 => DynamicImage::ImageRgb8(
            image::RgbImage::from_raw(width, height, data).ok_or_else(invalid_image)?,
        ),
        jpeg_decoder::PixelFormat::L8 => DynamicImage::ImageLuma8(
            image::GrayImage::from_raw(width, height, data).ok_or_else(invalid_image)?,
        ),
        jpeg_decoder::PixelFormat::L16 => {
            let samples = data
                .chunks_exact(2)
                .map(|pair| u16::from_ne_bytes([pair[0], pair[1]]))
                .collect();
            DynamicImage::ImageLuma16(
                image::ImageBuffer::from_raw(width, height, samples).ok_or_else(invalid_image)?,
            )
        }
        jpeg_decoder::PixelFormat::CMYK32 => {
            let mut rgb = Vec::with_capacity(width as usize * height as usize * 3);
            for pixel in data.chunks_exact(4) {
                let k = 255 - u16::from(pixel[3]);
                rgb.extend(
                    pixel[..3]
                        .iter()
                        .map(|&channel| ((255 - u16::from(channel)) * k / 255) as u8),
                );
            }
            DynamicImage::ImageRgb8(
                image::RgbImage::from_raw(width, height, rgb).ok_or_else(invalid_image)?,
            )
        }
    };
    Ok((image, orientation))
}

struct CancellableImageReader<'a, R> {
    inner: R,
    cancel: &'a CancellationToken,
}

impl<R: Read> Read for CancellableImageReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.cancel.is_cancelled() {
            return Err(io::Error::other("image decode cancelled"));
        }
        self.inner.read(buffer)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountReads<R> {
        inner: R,
        bytes: Arc<AtomicUsize>,
    }

    impl<R: Read> Read for CountReads<R> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = self.inner.read(buffer)?;
            self.bytes.fetch_add(count, Ordering::Relaxed);
            Ok(count)
        }
    }

    #[test]
    fn jpeg_decoder_does_not_materialize_the_complete_encoded_stream() {
        let mut jpeg = Vec::new();
        image::codecs::jpeg::JpegEncoder::new(&mut jpeg)
            .encode_image(&DynamicImage::new_rgb8(16, 12))
            .unwrap();
        let consumed = Arc::new(AtomicUsize::new(0));
        // A complete image followed by a large tail catches read_to_end without
        // allocating that tail in the test itself.
        let reader = CountReads {
            inner: io::Cursor::new(jpeg).chain(io::repeat(0).take(32 * 1024 * 1024)),
            bytes: Arc::clone(&consumed),
        };
        let (decoded, _) = decode_jpeg(reader, &CancellationToken::new()).unwrap();
        assert_eq!((decoded.width(), decoded.height()), (16, 12));
        assert!(consumed.load(Ordering::Relaxed) < 64 * 1024);
    }

    #[test]
    fn encoding_writer_never_retains_bytes_past_its_budget() {
        let mut writer = BoundedImageWriter {
            bytes: Vec::new(),
            limit: 4,
            exceeded: false,
        };
        writer.write_all(&[1, 2, 3]).unwrap();
        assert!(writer.write_all(&[4, 5]).is_err());
        assert_eq!(writer.bytes, [1, 2, 3]);
        assert!(writer.exceeded);
    }
}
