//! Port of gzip.c: z_readfile inflates a gzip or zlib file (zlib windowBits 47 auto-detects).

use flate2::{Decompress, FlushDecompress, Status};
use std::io::Read;

pub const Z_OK: i32 = 0;
pub const Z_STREAM_END: i32 = 1;
pub const Z_ERRNO: i32 = -1;
pub const Z_DATA_ERROR: i32 = -3;
pub const Z_BUF_ERROR: i32 = -5;

const ZCHUNK: usize = 16384;
const BUFMIN: usize = 128;
const BUFCHUNK: usize = 1024 * 128;

/// Returns (zlib result code, data). Data is meaningful when the code is Z_OK or Z_STREAM_END,
/// as in the C function (which frees the buffer on error).
pub fn z_readfile<R: Read>(f: &mut R) -> (i32, Vec<u8>) {
    let mut first = true;
    let mut z: Option<Decompress> = None;
    let mut buf: Vec<u8> = Vec::new();
    let mut r;
    loop {
        let mut inb = vec![0u8; ZCHUNK];
        let mut rd = 0;
        while rd < ZCHUNK {
            match f.read(&mut inb[rd..]) {
                Ok(0) => break,
                Ok(n) => rd += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return (Z_ERRNO, Vec::new()),
            }
        }
        if rd == 0 {
            return (Z_DATA_ERROR, Vec::new());
        }
        let inb = &inb[..rd];
        if first {
            first = false;
            let gz = inb.len() >= 2 && inb[0] == 0x1F && inb[1] == 0x8B;
            z = Some(if gz {
                Decompress::new_gzip(15)
            } else {
                Decompress::new(true)
            });
        }
        let Some(zs) = z.as_mut() else {
            return (Z_DATA_ERROR, Vec::new());
        };
        let mut pos = 0usize;
        loop {
            if buf.capacity() - buf.len() < BUFMIN {
                buf.reserve_exact(BUFCHUNK);
            }
            let tin = zs.total_in();
            let tout = zs.total_out();
            let st = zs.decompress_vec(&inb[pos..], &mut buf, FlushDecompress::None);
            pos += (zs.total_in() - tin) as usize;
            match st {
                Ok(Status::StreamEnd) => {
                    r = Z_STREAM_END;
                    break;
                }
                Ok(Status::BufError) => {
                    if pos < inb.len() {
                        return (Z_BUF_ERROR, Vec::new());
                    }
                    r = Z_OK;
                    break;
                }
                Ok(Status::Ok) => {
                    if pos >= inb.len() && zs.total_out() == tout && buf.len() < buf.capacity() {
                        // all input consumed and no progress: zlib reports Z_BUF_ERROR next
                        r = Z_OK;
                        break;
                    }
                }
                Err(_) => return (Z_DATA_ERROR, Vec::new()),
            }
        }
        if r != Z_OK {
            break;
        }
    }
    (r, buf)
}

pub fn is_gzip_bytes(head: &[u8]) -> bool {
    head.len() >= 2 && head[0] == 0x1F && head[1] == 0x8B
}

pub fn is_gzip_file(path: &str) -> bool {
    let mut m = [0u8; 2];
    match std::fs::File::open(path) {
        Ok(mut f) => f.read_exact(&mut m).is_ok() && is_gzip_bytes(&m),
        Err(_) => false,
    }
}
