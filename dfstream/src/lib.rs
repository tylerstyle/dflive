//! dfstream/1: authenticated, encrypted streams from a running system to a
//! dfnix receiver.
//!
//! - Pairing: the receiver shows a 10-digit code; both sides run SPAKE2 on it
//!   (Ed25519 group, sender as side A, receiver as side B), so an eavesdropper
//!   learns nothing and an active attacker tests one guess per connection.
//! - Keys: HKDF-SHA256 over the SPAKE2 key, salted with the handshake
//!   transcript; one key per direction and one for key confirmation, which
//!   both sides check before anything else is sent.
//! - Frames: `u32` big-endian length, then ChaCha20-Poly1305 ciphertext of
//!   `type ‖ payload` with a per-direction counter as nonce.
//! - Streams: `START`, `DATA`…, `END` with the sender's byte count and
//!   SHA-256; the receiver answers `RESULT` with its own.

use anyhow::{ensure, Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::io::{Read, Write};

pub const PROTOCOL: &str = "dfstream/1";
const MAGIC: &[u8; 4] = b"DFS1";
/// Bytes of stream data per frame
pub const CHUNK: usize = 1 << 20;
const MAX_PLAIN: usize = CHUNK + 1;
/// ChaCha20-Poly1305 tag
const TAG: usize = 16;
pub const CODE_DIGITS: usize = 10;

pub const HELLO: u8 = 1;
pub const START: u8 = 2;
pub const DATA: u8 = 3;
pub const END: u8 = 4;
pub const RESULT: u8 = 5;
pub const BYE: u8 = 6;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A pairing code of [`CODE_DIGITS`] decimal digits from the OS RNG, uniform
/// (rejection sampling).
pub fn pairing_code() -> Result<String> {
    let modulus = 10u64.pow(CODE_DIGITS as u32);
    let limit = u64::MAX - u64::MAX % modulus;
    loop {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("OS random generator: {e}"))?;
        let v = u64::from_be_bytes(b);
        if v < limit {
            return Ok(format!("{:0width$}", v % modulus, width = CODE_DIGITS));
        }
    }
}

/// The code as typed: digits, with spaces and dashes allowed for readability.
pub fn normalize_code(code: &str) -> Result<String> {
    let digits: String = code.chars().filter(|c| !matches!(c, ' ' | '-')).collect();
    ensure!(
        digits.len() == CODE_DIGITS && digits.bytes().all(|b| b.is_ascii_digit()),
        "the pairing code has {CODE_DIGITS} digits"
    );
    Ok(digits)
}

/// A file name from a sender-supplied stream name: letters, digits, `.`, `-`
/// and `_` (anything else becomes `_`), no leading dot, at most 80
/// characters; never empty.
pub fn sanitize_name(name: &str) -> String {
    let clean: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .take(80)
        .collect();
    let clean = clean.trim_start_matches('.');
    if clean.is_empty() {
        "stream".into()
    } else {
        clean.to_string()
    }
}

/// The code grouped for display: `123 456 7890`.
pub fn display_code(code: &str) -> String {
    format!("{} {} {}", &code[..3], &code[3..6], &code[6..])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Connects and sends the data (dflive)
    Sender,
    /// Listens and stores the data (dfnet)
    Receiver,
}

struct Direction {
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl Direction {
    fn new(key: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            cipher: ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| anyhow::anyhow!("bad key length"))?,
            counter: 0,
        })
    }

    fn nonce(&mut self) -> Result<[u8; 12]> {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&self.counter.to_be_bytes());
        self.counter = self
            .counter
            .checked_add(1)
            .context("frame counter exhausted")?;
        Ok(n)
    }
}

/// An authenticated, encrypted connection.
pub struct Channel<S> {
    stream: S,
    send: Direction,
    recv: Direction,
    /// SHA-256 of the handshake transcript, the same on both sides
    pub session_id: String,
}

fn write_handshake(stream: &mut impl Write, msg: &[u8]) -> Result<()> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&u16::try_from(msg.len())?.to_be_bytes());
    out.extend_from_slice(msg);
    stream.write_all(&out)?;
    stream.flush()?;
    Ok(())
}

fn read_handshake(stream: &mut impl Read) -> Result<Vec<u8>> {
    let mut head = [0u8; 6];
    stream
        .read_exact(&mut head)
        .context("the peer closed the connection during the handshake")?;
    ensure!(&head[..4] == MAGIC, "the peer does not speak {PROTOCOL}");
    let len = u16::from_be_bytes([head[4], head[5]]) as usize;
    ensure!(len <= 256, "handshake message too long");
    let mut msg = vec![0u8; len];
    stream.read_exact(&mut msg)?;
    Ok(msg)
}

fn confirm_tag(key: &[u8], label: &[u8], transcript: &[u8]) -> Result<[u8; 32]> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|_| anyhow::anyhow!("bad confirmation key"))?;
    mac.update(label);
    mac.update(transcript);
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&mac.finalize().into_bytes());
    Ok(tag)
}

/// Constant-time comparison of two tags.
fn tags_equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Run the pairing handshake on `stream`. Fails, without revealing anything
/// useful, when the other side used another code.
pub fn handshake<S: Read + Write>(mut stream: S, code: &str, role: Role) -> Result<Channel<S>> {
    let code = normalize_code(code)?;
    let password = Password::new(code.as_bytes());
    let (id_a, id_b) = (
        Identity::new(b"dfstream/1 sender"),
        Identity::new(b"dfstream/1 receiver"),
    );
    // Distinct roles at the PAKE layer: a reflected message cannot pair
    let (state, mine) = match role {
        Role::Sender => Spake2::<Ed25519Group>::start_a(&password, &id_a, &id_b),
        Role::Receiver => Spake2::<Ed25519Group>::start_b(&password, &id_a, &id_b),
    };
    // The sender speaks first
    let theirs = match role {
        Role::Sender => {
            write_handshake(&mut stream, &mine)?;
            read_handshake(&mut stream)?
        }
        Role::Receiver => {
            let theirs = read_handshake(&mut stream)?;
            write_handshake(&mut stream, &mine)?;
            theirs
        }
    };
    let shared = state
        .finish(&theirs)
        .map_err(|e| anyhow::anyhow!("pairing failed: {e:?}"))?;
    let (sender_msg, receiver_msg) = match role {
        Role::Sender => (&mine, &theirs),
        Role::Receiver => (&theirs, &mine),
    };
    let mut t = Sha256::new();
    t.update(MAGIC);
    t.update(sender_msg);
    t.update(receiver_msg);
    let transcript = t.finalize();

    let hk = hkdf::Hkdf::<Sha256>::new(Some(&transcript), &shared);
    let expand = |label: &[u8]| -> Result<[u8; 32]> {
        let mut out = [0u8; 32];
        hk.expand(label, &mut out)
            .map_err(|_| anyhow::anyhow!("HKDF expand"))?;
        Ok(out)
    };
    let s2r = expand(b"dfstream/1 sender to receiver")?;
    let r2s = expand(b"dfstream/1 receiver to sender")?;
    let confirm = expand(b"dfstream/1 confirmation")?;

    let sender_tag = confirm_tag(&confirm, b"sender", &transcript)?;
    let receiver_tag = confirm_tag(&confirm, b"receiver", &transcript)?;
    let wrong = || anyhow::anyhow!("pairing failed: the other side used a different code");
    match role {
        Role::Sender => {
            stream.write_all(&sender_tag)?;
            stream.flush()?;
            let mut got = [0u8; 32];
            stream.read_exact(&mut got).map_err(|_| wrong())?;
            ensure!(tags_equal(&got, &receiver_tag), wrong());
        }
        Role::Receiver => {
            let mut got = [0u8; 32];
            stream.read_exact(&mut got).map_err(|_| wrong())?;
            ensure!(tags_equal(&got, &sender_tag), wrong());
            stream.write_all(&receiver_tag)?;
            stream.flush()?;
        }
    }
    let (send_key, recv_key) = match role {
        Role::Sender => (s2r, r2s),
        Role::Receiver => (r2s, s2r),
    };
    Ok(Channel {
        stream,
        send: Direction::new(&send_key)?,
        recv: Direction::new(&recv_key)?,
        session_id: hex(&transcript),
    })
}

impl<S: Read + Write> Channel<S> {
    pub fn send(&mut self, ty: u8, payload: &[u8]) -> Result<()> {
        ensure!(payload.len() < MAX_PLAIN, "frame too large");
        let mut plain = Vec::with_capacity(payload.len() + 1);
        plain.push(ty);
        plain.extend_from_slice(payload);
        let nonce = self.send.nonce()?;
        let sealed = self
            .send
            .cipher
            .encrypt(&nonce.into(), plain.as_slice())
            .map_err(|_| anyhow::anyhow!("encryption failed"))?;
        self.stream
            .write_all(&u32::try_from(sealed.len())?.to_be_bytes())?;
        self.stream.write_all(&sealed)?;
        Ok(())
    }

    pub fn send_json(&mut self, ty: u8, value: &impl Serialize) -> Result<()> {
        self.send(ty, &serde_json::to_vec(value)?)
    }

    pub fn flush(&mut self) -> Result<()> {
        self.stream.flush()?;
        Ok(())
    }

    /// The next frame. A frame that fails authentication (tampered, replayed,
    /// reordered, from another session) ends the session.
    pub fn recv(&mut self) -> Result<(u8, Vec<u8>)> {
        let mut len = [0u8; 4];
        self.stream
            .read_exact(&mut len)
            .context("the connection ended")?;
        let len = u32::from_be_bytes(len) as usize;
        ensure!(
            (1 + TAG..=MAX_PLAIN + TAG).contains(&len),
            "frame length {len} out of range"
        );
        let mut sealed = vec![0u8; len];
        self.stream
            .read_exact(&mut sealed)
            .context("the connection ended inside a frame")?;
        let nonce = self.recv.nonce()?;
        let plain = self
            .recv
            .cipher
            .decrypt(&nonce.into(), sealed.as_slice())
            .map_err(|_| anyhow::anyhow!("a frame failed authentication; session ended"))?;
        Ok((plain[0], plain[1..].to_vec()))
    }

    pub fn recv_json<T: serde::de::DeserializeOwned>(&mut self, want: u8) -> Result<T> {
        let (ty, payload) = self.recv()?;
        ensure!(ty == want, "expected frame type {want}, got {ty}");
        Ok(serde_json::from_slice(&payload)?)
    }

    pub fn get_ref(&self) -> &S {
        &self.stream
    }
}

/// Who is sending, as the sender says.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hello {
    pub tool: String,
    pub version: String,
    pub host: String,
    pub os: String,
    /// The sender's clock, RFC 3339
    pub clock: String,
}

/// What a stream is.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Start {
    pub id: u32,
    /// `disk`, `volume`, `memory`, `file`
    pub kind: String,
    /// Name for the receiver's file (sanitized there)
    pub name: String,
    /// What was read: path, device, serial, model, ...
    #[serde(default)]
    pub source: serde_json::Value,
    /// Bytes expected, if known
    #[serde(default)]
    pub size: Option<u64>,
}

/// An area the sender could not read and replaced by zeros.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadError {
    pub offset: u64,
    pub length: u64,
}

/// The sender's account of a stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct End {
    pub id: u32,
    pub bytes: u64,
    pub sha256: String,
    /// Areas the sender replaced by zeros
    #[serde(default)]
    pub read_errors: Vec<ReadError>,
    /// Why the sender stopped before the end of the source
    #[serde(default)]
    pub stopped: Option<String>,
}

/// The receiver's account of a stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    pub id: u32,
    pub bytes: u64,
    pub sha256: String,
    /// `complete` (counts and hashes match), `mismatch` or `incomplete`
    pub status: String,
}

/// Send one stream from `source`, then wait for the receiver's outcome. A read
/// error ends the stream (`stopped`); a reader that zero-fills unreadable
/// areas reports them through `read_errors`, called once at the end.
pub fn send_stream<S: Read + Write>(
    ch: &mut Channel<S>,
    start: &Start,
    source: &mut impl Read,
    read_errors: impl FnOnce() -> Vec<ReadError>,
) -> Result<(End, Outcome)> {
    ch.send_json(START, start)?;
    let mut h = Sha256::new();
    let mut bytes = 0u64;
    let mut stopped = None;
    let mut buf = vec![0u8; CHUNK];
    loop {
        match source.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                h.update(&buf[..n]);
                ch.send(DATA, &buf[..n])?;
                bytes += n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                stopped = Some(format!("read error at byte {bytes}: {e}"));
                break;
            }
        }
    }
    let end = End {
        id: start.id,
        bytes,
        sha256: hex(&h.finalize()),
        read_errors: read_errors(),
        stopped,
    };
    ch.send_json(END, &end)?;
    ch.flush()?;
    let outcome: Outcome = ch.recv_json(RESULT)?;
    ensure!(outcome.id == start.id, "RESULT for another stream");
    Ok((end, outcome))
}

/// What the receiver got of one stream.
pub struct Received {
    pub start: Start,
    pub bytes: u64,
    pub sha256: String,
    /// `None` when the stream ended without the sender's END
    pub end: Option<End>,
    /// Why the stream ended early, if it did
    pub broken: Option<String>,
}

impl Received {
    /// `complete` only when END arrived, the sender did not stop early, and
    /// byte counts and hashes agree.
    pub fn status(&self) -> &'static str {
        match &self.end {
            None => "incomplete",
            Some(e) if e.stopped.is_some() => "incomplete",
            Some(e) if e.bytes == self.bytes && e.sha256 == self.sha256 => "complete",
            Some(_) => "mismatch",
        }
    }
}

/// Receive the stream announced by `start` into `sink`, then answer RESULT.
/// Anything from the sender that breaks the stream (a broken or tampered
/// connection, a malformed or foreign END, an unexpected frame) returns what
/// arrived with `end: None` and the reason in `broken`. Only a failure to
/// write `sink` is an error.
pub fn receive_stream<S: Read + Write>(
    ch: &mut Channel<S>,
    start: Start,
    sink: &mut impl Write,
) -> Result<Received> {
    let mut h = Sha256::new();
    let mut bytes = 0u64;
    let mut broken = None;
    let end = loop {
        let (ty, payload) = match ch.recv() {
            Ok(f) => f,
            Err(e) => {
                broken = Some(format!("{e:#}"));
                break None;
            }
        };
        match ty {
            DATA => {
                sink.write_all(&payload).context("writing the stream")?;
                h.update(&payload);
                bytes += payload.len() as u64;
            }
            END => match serde_json::from_slice::<End>(&payload) {
                Ok(end) if end.id == start.id => break Some(end),
                Ok(end) => {
                    broken = Some(format!(
                        "END for stream {} inside stream {}",
                        end.id, start.id
                    ));
                    break None;
                }
                Err(e) => {
                    broken = Some(format!("unreadable END: {e}"));
                    break None;
                }
            },
            other => {
                broken = Some(format!(
                    "unexpected frame type {other} inside stream {}",
                    start.id
                ));
                break None;
            }
        }
    };
    sink.flush()?;
    let received = Received {
        start,
        bytes,
        sha256: hex(&h.finalize()),
        end,
        broken,
    };
    if received.end.is_some() {
        // The receiver's record does not depend on the sender hearing it
        let _ = ch
            .send_json(
                RESULT,
                &Outcome {
                    id: received.start.id,
                    bytes: received.bytes,
                    sha256: received.sha256.clone(),
                    status: received.status().into(),
                },
            )
            .and_then(|()| ch.flush());
    }
    Ok(received)
}

#[cfg(test)]
mod tests;
