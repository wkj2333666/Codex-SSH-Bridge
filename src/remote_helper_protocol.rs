//! Synchronous CXSB1 framing used by the precompiled remote helper.
//!
//! The bridge's normal session reader is asynchronous and intentionally keeps
//! its existing private API.  This small std-only implementation is shared by
//! the helper binary and its local wire-conformance tests.

use std::io::{self, BufRead, Write};

const MAGIC: &str = "CXSB1";
const MAX_HEADER_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
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
pub struct Frame {
    pub kind: FrameKind,
    pub request_id: u64,
    pub payload: Vec<u8>,
}

pub fn read_frame<R: BufRead>(reader: &mut R, max_payload: usize) -> io::Result<Option<Frame>> {
    let mut header = Vec::with_capacity(64);
    loop {
        let buffered = reader.fill_buf()?;
        if buffered.is_empty() {
            if header.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated SSH bridge frame header",
            ));
        }

        let newline = buffered.iter().position(|byte| *byte == b'\n');
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
    let mut payload = vec![0; payload_len];
    reader.read_exact(&mut payload).map_err(|error| {
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

pub fn write_frame<W: Write>(writer: &mut W, frame: &Frame, max_payload: usize) -> io::Result<()> {
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
    writer.write_all(header.as_bytes())?;
    writer.write_all(&frame.payload)
}
