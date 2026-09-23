use std::io;

use memchr::memchr;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAGIC: &str = "CXSB1";
const MAX_HEADER_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrameKind {
    Hello,
    HelloAck,
    Open,
    Data,
    Cancel,
    Close,
    Ready,
    Stdout,
    Stderr,
    Exit,
    Error,
}

impl FrameKind {
    fn as_token(self) -> &'static str {
        match self {
            Self::Hello => "HELLO",
            Self::HelloAck => "HELLO_ACK",
            Self::Open => "OPEN",
            Self::Data => "DATA",
            Self::Cancel => "CANCEL",
            Self::Close => "CLOSE",
            Self::Ready => "READY",
            Self::Stdout => "STDOUT",
            Self::Stderr => "STDERR",
            Self::Exit => "EXIT",
            Self::Error => "ERROR",
        }
    }

    fn from_token(token: &str) -> Option<Self> {
        Some(match token {
            "HELLO" => Self::Hello,
            "HELLO_ACK" => Self::HelloAck,
            "OPEN" => Self::Open,
            "DATA" => Self::Data,
            "CANCEL" => Self::Cancel,
            "CLOSE" => Self::Close,
            "READY" => Self::Ready,
            "STDOUT" => Self::Stdout,
            "STDERR" => Self::Stderr,
            "EXIT" => Self::Exit,
            "ERROR" => Self::Error,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Frame {
    pub(crate) kind: FrameKind,
    pub(crate) request_id: u64,
    pub(crate) payload: Vec<u8>,
}

pub(crate) async fn read_frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max_payload: usize,
) -> io::Result<Option<Frame>> {
    let mut header = Vec::with_capacity(64);
    loop {
        let buffered = reader.fill_buf().await?;
        if buffered.is_empty() {
            if header.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated SSH bridge frame header",
            ));
        }

        let newline = memchr(b'\n', buffered);
        let content_len = newline.unwrap_or(buffered.len());
        let remaining = MAX_HEADER_BYTES - header.len();
        let accepted = content_len.min(remaining);
        if buffered[..accepted]
            .iter()
            .any(|byte| !(0x20..0x7f).contains(byte))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SSH bridge frame header is not ASCII",
            ));
        }
        if content_len > remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SSH bridge frame header exceeds the configured bound",
            ));
        }
        header.extend_from_slice(&buffered[..content_len]);
        reader.consume(content_len + usize::from(newline.is_some()));
        if newline.is_some() {
            break;
        }
    }

    let header = std::str::from_utf8(&header).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "SSH bridge frame header is not UTF-8",
        )
    })?;
    let mut fields = header.split_ascii_whitespace();
    let magic = fields.next();
    let kind = fields.next();
    let request_id = fields.next();
    let payload_len = fields.next();
    if magic != Some(MAGIC)
        || fields.next().is_some()
        || kind.is_none()
        || request_id.is_none()
        || payload_len.is_none()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed SSH bridge frame header",
        ));
    }
    let kind = FrameKind::from_token(kind.unwrap()).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "unknown SSH bridge frame kind")
    })?;
    let request_id = request_id.unwrap().parse::<u64>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SSH bridge frame request id",
        )
    })?;
    let payload_len = payload_len.unwrap().parse::<usize>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SSH bridge frame payload length",
        )
    })?;
    if payload_len > max_payload {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SSH bridge frame payload exceeds the configured bound",
        ));
    }

    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload).await.map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated SSH bridge frame payload",
            )
        } else {
            error
        }
    })?;
    Ok(Some(Frame {
        kind,
        request_id,
        payload,
    }))
}

pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &Frame,
    max_payload: usize,
) -> io::Result<()> {
    if frame.payload.len() > max_payload {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SSH bridge frame payload exceeds the configured bound",
        ));
    }
    let header = format!(
        "{MAGIC} {} {} {}\n",
        frame.kind.as_token(),
        frame.request_id,
        frame.payload.len()
    );
    if header.len() > MAX_HEADER_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SSH bridge frame header exceeds the configured bound",
        ));
    }
    writer.write_all(header.as_bytes()).await?;
    writer.write_all(&frame.payload).await
}

#[cfg(test)]
mod tests {
    use super::{Frame, FrameKind, read_frame, write_frame};
    use std::io::Cursor;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, duplex};

    fn frame(kind: FrameKind, request_id: u64, payload: &[u8]) -> Frame {
        Frame {
            kind,
            request_id,
            payload: payload.to_vec(),
        }
    }

    #[tokio::test]
    async fn binary_payload_round_trips_and_empty_payload_is_valid() {
        let mut wire = Vec::new();
        let mut writer = Cursor::new(&mut wire);
        write_frame(
            &mut writer,
            &frame(FrameKind::Stdout, 17, &[0, 1, b'\n', 0xff]),
            64,
        )
        .await
        .unwrap();
        write_frame(&mut writer, &frame(FrameKind::Ready, 17, &[]), 64)
            .await
            .unwrap();

        let mut reader = BufReader::new(Cursor::new(wire));
        assert_eq!(
            read_frame(&mut reader, 64).await.unwrap(),
            Some(frame(FrameKind::Stdout, 17, &[0, 1, b'\n', 0xff]))
        );
        assert_eq!(
            read_frame(&mut reader, 64).await.unwrap(),
            Some(frame(FrameKind::Ready, 17, &[]))
        );
        assert_eq!(read_frame(&mut reader, 64).await.unwrap(), None);
    }

    #[tokio::test]
    async fn fragmented_header_and_payload_are_reassembled() {
        let (mut tx, rx) = duplex(64);
        let expected = frame(FrameKind::Stderr, 9, &[0, 0, 0xff, b'\n']);
        let bytes = b"CXSB1 STDERR 9 4\n\0\0\xff\n".to_vec();
        let writer = tokio::spawn(async move {
            for chunk in bytes.chunks(1) {
                tx.write_all(chunk).await.unwrap();
            }
        });
        let mut reader = BufReader::new(rx);
        assert_eq!(read_frame(&mut reader, 64).await.unwrap(), Some(expected));
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn multiple_frames_in_one_read_keep_order() {
        let wire = b"CXSB1 READY 1 0\nCXSB1 EXIT 1 2\n\x01\xff".to_vec();
        let mut reader = BufReader::new(Cursor::new(wire));
        assert_eq!(
            read_frame(&mut reader, 64).await.unwrap(),
            Some(frame(FrameKind::Ready, 1, &[]))
        );
        assert_eq!(
            read_frame(&mut reader, 64).await.unwrap(),
            Some(frame(FrameKind::Exit, 1, &[1, 0xff]))
        );
    }

    #[tokio::test]
    async fn malformed_headers_are_rejected_without_allocating_payload() {
        for wire in [
            b"CXSB0 READY 1 0\n".to_vec(),
            b"CXSB1 UNKNOWN 1 0\n".to_vec(),
            b"CXSB1 READY nope 0\n".to_vec(),
            b"CXSB1 READY 1 nope\n".to_vec(),
            b"CXSB1 READY 1 0 extra\n".to_vec(),
        ] {
            let mut reader = BufReader::new(Cursor::new(wire));
            assert!(read_frame(&mut reader, 64).await.is_err());
        }
    }

    #[tokio::test]
    async fn oversized_and_truncated_frames_are_rejected() {
        let mut oversized = BufReader::new(Cursor::new(b"CXSB1 DATA 1 65\n".to_vec()));
        assert!(read_frame(&mut oversized, 64).await.is_err());

        let mut truncated = BufReader::new(Cursor::new(b"CXSB1 DATA 1 4\nabc".to_vec()));
        assert!(read_frame(&mut truncated, 64).await.is_err());
    }

    #[tokio::test]
    async fn writer_rejects_payloads_above_bound() {
        let mut output = Vec::new();
        let mut writer = Cursor::new(&mut output);
        let error = write_frame(&mut writer, &frame(FrameKind::Data, 1, &[0; 65]), 64)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn clean_eof_is_distinguished_from_partial_header() {
        let mut clean = BufReader::new(Cursor::new(Vec::<u8>::new()));
        assert_eq!(read_frame(&mut clean, 64).await.unwrap(), None);

        let mut partial = BufReader::new(Cursor::new(b"CXSB1 READY".to_vec()));
        assert!(read_frame(&mut partial, 64).await.is_err());
    }

    #[tokio::test]
    async fn header_scan_preserves_ascii_and_exact_size_boundaries() {
        let mut exact = vec![b' '; super::MAX_HEADER_BYTES];
        exact.push(b'\n');
        let error = read_frame(&mut BufReader::new(Cursor::new(exact)), 64)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "malformed SSH bridge frame header");

        let mut oversized = vec![b' '; super::MAX_HEADER_BYTES + 1];
        oversized.push(b'\n');
        let error = read_frame(&mut BufReader::new(Cursor::new(oversized)), 64)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "SSH bridge frame header exceeds the configured bound"
        );

        let error = read_frame(
            &mut BufReader::new(Cursor::new(b"CXSB1 READY 1 \xff\n".to_vec())),
            64,
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "SSH bridge frame header is not ASCII");
    }

    #[allow(dead_code)]
    async fn _read_all(mut reader: impl tokio::io::AsyncRead + Unpin) -> Vec<u8> {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await.unwrap();
        bytes
    }
}
