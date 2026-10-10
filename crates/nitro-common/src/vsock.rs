//! Length-prefixed framing for the enclave VSOCK API: a 4-byte
//! big-endian length followed by that many payload bytes. A per-frame
//! size guard rejects oversized declarations before allocating, and a
//! deadline variant bounds total read time on a blocking `TcpStream`.

use eyre::{eyre, Result};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Instant;

/// Default frame ceiling (64 KiB), matching the oracle price server.
pub const MAX_FRAME: usize = 64 * 1024;

/// Write `payload` as a length-prefixed frame. Errors if `payload`
/// exceeds `max_frame` (so a bug cannot emit a frame a conforming reader
/// would reject).
pub fn write_frame<W: Write>(w: &mut W, payload: &[u8], max_frame: usize) -> Result<()> {
    if payload.len() > max_frame {
        return Err(eyre!(
            "frame too large: {} bytes (max {})",
            payload.len(),
            max_frame
        ));
    }
    w.write_all(&(payload.len() as u32).to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

/// Read one length-prefixed frame. Rejects a declared length above
/// `max_frame` before allocating the buffer.
pub fn read_frame<R: Read>(r: &mut R, max_frame: usize) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_frame {
        return Err(eyre!("frame too large: {} bytes (max {})", len, max_frame));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Read one length-prefixed frame from a blocking `TcpStream`, bailing if
/// total elapsed time exceeds `deadline` regardless of per-byte progress.
/// The OS read timeout is shrunk to the remaining budget on each syscall,
/// so a drip-feeder still hits the wall.
pub fn read_frame_deadline(
    stream: &mut TcpStream,
    max_frame: usize,
    deadline: Instant,
) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    read_exact_deadline(stream, &mut len_buf, deadline)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_frame {
        return Err(eyre!("frame too large: {} bytes (max {})", len, max_frame));
    }
    let mut buf = vec![0u8; len];
    read_exact_deadline(stream, &mut buf, deadline)?;
    Ok(buf)
}

fn read_exact_deadline(stream: &mut TcpStream, buf: &mut [u8], deadline: Instant) -> Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let now = Instant::now();
        if now >= deadline {
            return Err(eyre!("frame read deadline exceeded"));
        }
        stream.set_read_timeout(Some(deadline - now))?;
        match stream.read(&mut buf[filled..]) {
            Ok(0) => return Err(eyre!("connection closed mid-read")),
            Ok(n) => filled += n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(eyre!("frame read timed out"));
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip_preserves_payload() {
        let payload = b"the registry is the arbiter".to_vec();
        let mut wire = Vec::new();
        write_frame(&mut wire, &payload, MAX_FRAME).unwrap();
        // 4-byte prefix + body.
        assert_eq!(wire.len(), 4 + payload.len());
        let mut r = Cursor::new(wire);
        let got = read_frame(&mut r, MAX_FRAME).unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn roundtrip_empty_frame() {
        let mut wire = Vec::new();
        write_frame(&mut wire, &[], MAX_FRAME).unwrap();
        let mut r = Cursor::new(wire);
        assert_eq!(read_frame(&mut r, MAX_FRAME).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn write_rejects_oversized_payload() {
        let mut wire = Vec::new();
        let err = write_frame(&mut wire, &[0u8; 17], 16).unwrap_err();
        assert!(err.to_string().contains("frame too large"));
        // Nothing partial was emitted.
        assert!(wire.is_empty());
    }

    #[test]
    fn read_rejects_oversized_declared_length() {
        // Declares 1 MiB but the reader cap is 16 bytes.
        let mut wire = (1024u32 * 1024).to_be_bytes().to_vec();
        wire.extend_from_slice(&[0u8; 8]);
        let mut r = Cursor::new(wire);
        let err = read_frame(&mut r, 16).unwrap_err();
        assert!(err.to_string().contains("frame too large"));
    }

    #[test]
    fn read_at_exact_cap_is_allowed() {
        let payload = vec![7u8; 16];
        let mut wire = Vec::new();
        write_frame(&mut wire, &payload, 16).unwrap();
        let mut r = Cursor::new(wire);
        assert_eq!(read_frame(&mut r, 16).unwrap(), payload);
    }

    #[test]
    fn read_truncated_body_errors() {
        let mut wire = 8u32.to_be_bytes().to_vec();
        wire.extend_from_slice(&[1, 2, 3]); // only 3 of 8 promised bytes
        let mut r = Cursor::new(wire);
        assert!(read_frame(&mut r, MAX_FRAME).is_err());
    }
}
