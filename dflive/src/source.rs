//! Reading a disk or volume so that an unreadable area costs only its own
//! sectors: a failed read is retried sector by sector, unreadable sectors are
//! replaced by zeros and listed, and every later byte keeps its offset.

use dfstream::ReadError;
use std::{
    cell::RefCell,
    fs::File,
    io::{self, Read},
    rc::Rc,
};

#[cfg(unix)]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, buf, offset)
}

#[cfg(windows)]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, buf, offset)
}

/// Fill `buf` from `offset`, or fail.
fn read_full_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    let mut done = 0;
    while done < buf.len() {
        match read_at(file, &mut buf[done..], offset + done as u64) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => done += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

pub struct ZeroFill {
    file: File,
    pos: u64,
    size: u64,
    sector: usize,
    errors: Rc<RefCell<Vec<ReadError>>>,
}

impl ZeroFill {
    /// `size` bytes of `file`; unreadable areas are found to `sector` bytes.
    pub fn new(file: File, size: u64, sector: usize) -> Self {
        Self {
            file,
            pos: 0,
            size,
            sector,
            errors: Rc::new(RefCell::new(Vec::new())),
        }
    }

    /// The zero-filled areas so far (shared, so it can be read after the
    /// reader was handed out).
    pub fn errors(&self) -> Rc<RefCell<Vec<ReadError>>> {
        Rc::clone(&self.errors)
    }

    fn record(&self, offset: u64, length: u64) {
        let mut errors = self.errors.borrow_mut();
        match errors.last_mut() {
            Some(last) if last.offset + last.length == offset => last.length += length,
            _ => errors.push(ReadError { offset, length }),
        }
    }
}

impl Read for ZeroFill {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size {
            return Ok(0);
        }
        let want = buf.len().min((self.size - self.pos) as usize);
        let buf = &mut buf[..want];
        if read_full_at(&self.file, buf, self.pos).is_err() {
            for (i, chunk) in buf.chunks_mut(self.sector).enumerate() {
                let offset = self.pos + (i * self.sector) as u64;
                if read_full_at(&self.file, chunk, offset).is_err() {
                    chunk.fill(0);
                    self.record(offset, chunk.len() as u64);
                }
            }
        }
        self.pos += want as u64;
        Ok(want)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_readable_file_reads_unchanged() {
        let path = std::env::temp_dir().join(format!("dflive_zerofill_{}", std::process::id()));
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &data).unwrap();
        let mut r = ZeroFill::new(File::open(&path).unwrap(), data.len() as u64, 512);
        let errors = r.errors();
        let mut out = Vec::new();
        let mut buf = vec![0u8; 4096];
        loop {
            let n = r.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        assert_eq!(out, data);
        assert!(errors.borrow().is_empty());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_shorter_file_is_zero_filled_past_its_end_and_listed() {
        // A size beyond the end of the file stands in for unreadable sectors
        let path =
            std::env::temp_dir().join(format!("dflive_zerofill_short_{}", std::process::id()));
        std::fs::write(&path, vec![7u8; 1500]).unwrap();
        let mut r = ZeroFill::new(File::open(&path).unwrap(), 4096, 512);
        let errors = r.errors();
        let mut out = vec![0u8; 8192];
        let n = r.read(&mut out).unwrap();
        assert_eq!(n, 4096);
        // Sectors 0-1 read whole; sector 2 (1024..1536) is short, so zeros
        assert_eq!(&out[..1024], &[7u8; 1024][..]);
        assert!(out[1024..4096].iter().all(|&b| b == 0));
        assert_eq!(
            *errors.borrow(),
            vec![ReadError {
                offset: 1024,
                length: 3072
            }]
        );
        assert_eq!(r.read(&mut out).unwrap(), 0);
        std::fs::remove_file(&path).unwrap();
    }
}
