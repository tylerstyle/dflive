use super::*;
use std::{io::Cursor, os::unix::net::UnixStream, thread};

const CODE: &str = "0123456789";

/// What the relay does with bytes from the sender.
enum Relay {
    /// Forward these bytes
    Pass(Vec<u8>),
    /// Forward these bytes, then close the connection to the receiver
    Close(Vec<u8>),
}

/// The handshake bytes the sender sends: magic, length, SPAKE2 message,
/// confirmation tag
const SENDER_HANDSHAKE: usize = 6 + 33 + 32;

/// A connection between sender and receiver through a relay that passes the
/// sender's bytes through `edit` (their position in the sender's byte stream
/// and the bytes) and the receiver's bytes unchanged.
fn relayed(mut edit: impl FnMut(u64, &[u8]) -> Relay + Send + 'static) -> (UnixStream, UnixStream) {
    let (sender, relay_s) = UnixStream::pair().unwrap();
    let (relay_r, receiver) = UnixStream::pair().unwrap();
    let (mut a_in, mut a_out) = (relay_s.try_clone().unwrap(), relay_s);
    let (mut b_in, mut b_out) = (relay_r.try_clone().unwrap(), relay_r);
    thread::spawn(move || {
        let mut pos = 0u64;
        let mut buf = [0u8; 4096];
        loop {
            let n = match a_in.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let (out, close) = match edit(pos, &buf[..n]) {
                Relay::Pass(b) => (b, false),
                Relay::Close(b) => (b, true),
            };
            pos += n as u64;
            if b_out.write_all(&out).is_err() || close {
                break;
            }
        }
        let _ = b_out.shutdown(std::net::Shutdown::Both);
        let _ = a_in.shutdown(std::net::Shutdown::Both);
    });
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            let n = match b_in.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if a_out.write_all(&buf[..n]).is_err() {
                break;
            }
        }
        let _ = a_out.shutdown(std::net::Shutdown::Write);
    });
    (sender, receiver)
}

fn start(id: u32, size: Option<u64>) -> Start {
    Start {
        id,
        kind: "file".into(),
        name: "test.bin".into(),
        source: serde_json::json!({ "path": "/test" }),
        size,
    }
}

fn data(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 % 251) as u8).collect()
}

#[test]
fn pairing_codes() {
    for _ in 0..100 {
        let c = pairing_code().unwrap();
        assert_eq!(c.len(), 10);
        assert!(c.bytes().all(|b| b.is_ascii_digit()));
    }
    assert_eq!(normalize_code("012 345-6789").unwrap(), "0123456789");
    assert!(normalize_code("012345678").is_err());
    assert!(normalize_code("01234567x9").is_err());
    assert_eq!(display_code("0123456789"), "012 345 6789");
}

#[test]
fn stream_names_cannot_leave_the_directory() {
    assert_eq!(sanitize_name("C:"), "C_");
    assert_eq!(sanitize_name("../../etc/passwd"), "_.._etc_passwd");
    assert_eq!(sanitize_name("...hidden"), "hidden");
    assert_eq!(sanitize_name(""), "stream");
    assert_eq!(sanitize_name("\\\\.\\PhysicalDrive0"), "__._PhysicalDrive0");
    for n in ["a/b", "..", "x\0y", "/abs", "."] {
        let f = sanitize_name(n);
        assert!(
            !f.contains('/') && !f.starts_with('.') && !f.is_empty(),
            "{f}"
        );
    }
}

#[test]
fn a_reflected_handshake_does_not_pair() {
    // A relay that sends the sender's own messages back to it
    let (s, r) = UnixStream::pair().unwrap();
    let mirror = thread::spawn(move || {
        let mut r = r;
        let mut buf = [0u8; 4096];
        while let Ok(n) = r.read(&mut buf) {
            if n == 0 || r.write_all(&buf[..n]).is_err() {
                break;
            }
        }
    });
    assert!(handshake(s, CODE, Role::Sender).is_err());
    mirror.join().unwrap();
}

#[test]
fn a_stream_arrives_complete_with_matching_hashes() {
    let (s, r) = UnixStream::pair().unwrap();
    let payload = data(3 * CHUNK + 12345);
    let sent = payload.clone();
    let sender = thread::spawn(move || {
        let mut ch = handshake(s, "012 345 6789", Role::Sender).unwrap();
        let id = ch.session_id.clone();
        let (end, outcome) = send_stream(
            &mut ch,
            &start(1, Some(sent.len() as u64)),
            &mut Cursor::new(&sent),
            Vec::new,
        )
        .unwrap();
        ch.send(BYE, &[]).unwrap();
        (id, end, outcome)
    });
    let mut ch = handshake(r, CODE, Role::Receiver).unwrap();
    let st: Start = ch.recv_json(START).unwrap();
    let mut sink = Vec::new();
    let got = receive_stream(&mut ch, st, &mut sink).unwrap();
    assert_eq!(ch.recv().unwrap().0, BYE);
    let (sender_id, end, outcome) = sender.join().unwrap();
    assert_eq!(sender_id, ch.session_id);
    assert_eq!(sink, payload);
    assert_eq!(got.status(), "complete");
    assert_eq!(end.sha256, got.sha256);
    assert_eq!(outcome.status, "complete");
    assert_eq!(outcome.bytes, payload.len() as u64);
}

#[test]
fn a_different_code_fails_on_both_sides() {
    let (s, r) = UnixStream::pair().unwrap();
    let sender = thread::spawn(move || handshake(s, "9999999999", Role::Sender).err());
    let err = handshake(r, CODE, Role::Receiver).err().unwrap();
    assert!(format!("{err:#}").contains("different code"), "{err:#}");
    assert!(sender.join().unwrap().is_some());
}

#[test]
fn a_tampered_frame_ends_the_stream_as_incomplete() {
    // Flip one byte well after the handshake, inside a DATA frame
    let (s, r) = relayed(|pos, bytes| {
        let mut bytes = bytes.to_vec();
        let target = 5_000u64;
        if pos <= target && target < pos + bytes.len() as u64 {
            bytes[(target - pos) as usize] ^= 0x01;
        }
        Relay::Pass(bytes)
    });
    let payload = data(CHUNK / 2);
    let sender = thread::spawn(move || {
        let mut ch = handshake(s, CODE, Role::Sender).unwrap();
        send_stream(
            &mut ch,
            &start(1, None),
            &mut Cursor::new(payload),
            Vec::new,
        )
        .err()
    });
    let mut ch = handshake(r, CODE, Role::Receiver).unwrap();
    let st: Start = ch.recv_json(START).unwrap();
    let got = receive_stream(&mut ch, st, &mut Vec::new()).unwrap();
    assert_eq!(got.status(), "incomplete");
    assert!(got.broken.unwrap().contains("authentication"));
    drop(ch);
    // The sender never gets a RESULT
    assert!(sender.join().unwrap().is_some());
}

#[test]
fn a_replayed_frame_is_refused() {
    // Duplicate the first frame after the handshake (the START frame)
    let (s, r) = relayed({
        let mut held = Vec::new();
        let mut done = false;
        move |pos, bytes| {
            let pos = pos as usize;
            if done || pos + bytes.len() <= SENDER_HANDSHAKE {
                return Relay::Pass(bytes.to_vec());
            }
            // Pass the handshake, hold back what follows until a frame is whole
            let split = SENDER_HANDSHAKE.saturating_sub(pos);
            let mut out = bytes[..split].to_vec();
            held.extend_from_slice(&bytes[split..]);
            if held.len() >= 4 {
                let len = u32::from_be_bytes(held[..4].try_into().unwrap()) as usize;
                if held.len() >= 4 + len {
                    done = true;
                    let frame = held[..4 + len].to_vec();
                    out.extend_from_slice(&frame);
                    out.extend_from_slice(&held);
                }
            }
            Relay::Pass(out)
        }
    });
    let sender = thread::spawn(move || {
        let mut ch = handshake(s, CODE, Role::Sender).unwrap();
        let _ = send_stream(
            &mut ch,
            &start(1, None),
            &mut Cursor::new(data(100)),
            Vec::new,
        );
    });
    let mut ch = handshake(r, CODE, Role::Receiver).unwrap();
    let st: Start = ch.recv_json(START).unwrap();
    let got = receive_stream(&mut ch, st, &mut Vec::new()).unwrap();
    assert_eq!(got.status(), "incomplete");
    assert!(got.broken.unwrap().contains("authentication"));
    drop(ch);
    sender.join().unwrap();
}

#[test]
fn a_cut_connection_is_incomplete() {
    // Deliver only the first 200 kB of the sender's bytes
    let (s, r) = relayed(|pos, bytes| {
        let keep = 200_000u64.saturating_sub(pos) as usize;
        if keep < bytes.len() {
            Relay::Close(bytes[..keep].to_vec())
        } else {
            Relay::Pass(bytes.to_vec())
        }
    });
    thread::spawn(move || {
        let mut ch = handshake(s, CODE, Role::Sender).unwrap();
        let _ = send_stream(
            &mut ch,
            &start(1, None),
            &mut Cursor::new(data(2 * CHUNK)),
            Vec::new,
        );
    });
    let mut ch = handshake(r, CODE, Role::Receiver).unwrap();
    let st: Start = ch.recv_json(START).unwrap();
    let mut sink = Vec::new();
    let got = receive_stream(&mut ch, st, &mut sink).unwrap();
    assert_eq!(got.status(), "incomplete");
    assert!(got.end.is_none());
}

#[test]
fn a_source_that_fails_is_reported_as_stopped() {
    struct Failing(usize);
    impl Read for Failing {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.0 == 0 {
                return Err(std::io::Error::other("bad sector"));
            }
            let n = self.0.min(buf.len());
            buf[..n].fill(7);
            self.0 -= n;
            Ok(n)
        }
    }
    let (s, r) = UnixStream::pair().unwrap();
    let sender = thread::spawn(move || {
        let mut ch = handshake(s, CODE, Role::Sender).unwrap();
        send_stream(&mut ch, &start(1, None), &mut Failing(1000), Vec::new).unwrap()
    });
    let mut ch = handshake(r, CODE, Role::Receiver).unwrap();
    let st: Start = ch.recv_json(START).unwrap();
    let got = receive_stream(&mut ch, st, &mut Vec::new()).unwrap();
    assert_eq!(got.status(), "incomplete");
    let (end, outcome) = sender.join().unwrap();
    assert!(end.stopped.unwrap().contains("bad sector"));
    assert_eq!(outcome.status, "incomplete");
    assert_eq!(outcome.bytes, 1000);
}

#[test]
fn a_hash_that_does_not_match_is_a_mismatch() {
    let (s, r) = UnixStream::pair().unwrap();
    let sender = thread::spawn(move || {
        let mut ch = handshake(s, CODE, Role::Sender).unwrap();
        ch.send_json(START, &start(1, None)).unwrap();
        ch.send(DATA, b"hello").unwrap();
        let end = End {
            id: 1,
            bytes: 5,
            sha256: "0".repeat(64),
            read_errors: vec![],
            stopped: None,
        };
        ch.send_json(END, &end).unwrap();
        ch.recv_json::<Outcome>(RESULT).unwrap()
    });
    let mut ch = handshake(r, CODE, Role::Receiver).unwrap();
    let st: Start = ch.recv_json(START).unwrap();
    let got = receive_stream(&mut ch, st, &mut Vec::new()).unwrap();
    assert_eq!(got.status(), "mismatch");
    assert_eq!(sender.join().unwrap().status, "mismatch");
}

#[test]
fn a_foreign_or_malformed_end_breaks_the_stream_without_an_error() {
    for end in [
        b"{\"id\": 9, \"bytes\": 0, \"sha256\": \"\"}".to_vec(),
        b"not json".to_vec(),
    ] {
        let (s, r) = UnixStream::pair().unwrap();
        let sender = thread::spawn(move || {
            let mut ch = handshake(s, CODE, Role::Sender).unwrap();
            ch.send_json(START, &start(1, None)).unwrap();
            ch.send(DATA, b"partial").unwrap();
            ch.send(END, &end).unwrap();
        });
        let mut ch = handshake(r, CODE, Role::Receiver).unwrap();
        let st: Start = ch.recv_json(START).unwrap();
        let got = receive_stream(&mut ch, st, &mut Vec::new()).unwrap();
        assert_eq!(got.status(), "incomplete");
        assert!(got.broken.is_some());
        sender.join().unwrap();
    }
}
