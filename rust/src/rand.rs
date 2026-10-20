//! Cryptographically secure random bytes from the OS. std-only: reads
//! /dev/urandom (Linux/Unix), the kernel CSPRNG.

use std::fs::File;
use std::io::Read;
use std::sync::Mutex;
use std::sync::OnceLock;

fn urandom() -> &'static Mutex<File> {
    static F: OnceLock<Mutex<File>> = OnceLock::new();
    F.get_or_init(|| Mutex::new(File::open("/dev/urandom").expect("cannot open /dev/urandom")))
}

/// Fill `buf` with random bytes, or panic if the OS RNG is unavailable.
pub fn fill(buf: &mut [u8]) {
    let mut f = urandom().lock().unwrap();
    f.read_exact(buf).expect("cannot read /dev/urandom");
}

pub fn bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    fill(&mut v);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_distinct_bytes() {
        let a = bytes(32);
        let b = bytes(32);
        assert_eq!(a.len(), 32);
        assert_ne!(a, b); // astronomically unlikely to collide
        assert!(a.iter().any(|&x| x != 0));
    }
}
