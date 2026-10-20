//! Hashes and KDFs implemented from their specifications, std-only:
//! SHA-1 (RFC 3174), SHA-256 (FIPS 180-4), HMAC (RFC 2104), PBKDF2 (RFC 8018)
//! and scrypt (RFC 7914), plus a constant-time comparison.
//!
//! Each primitive carries published test vectors (see the tests) so the
//! implementations can be checked against the standards without any dependency.

// -- SHA-256 ------------------------------------------------------------------

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub const SHA256_LEN: usize = 32;
pub const SHA256_BLOCK: usize = 64;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    let mut w = [0u32; 64];
    for block in msg.chunks_exact(64) {
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(t1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1.wrapping_add(t2);
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

// -- SHA-1 --------------------------------------------------------------------

pub const SHA1_LEN: usize = 20;
pub const SHA1_BLOCK: usize = 64;

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    let mut w = [0u32; 80];
    for block in msg.chunks_exact(64) {
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for i in 0..5 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

// -- HMAC ---------------------------------------------------------------------

fn hmac(block: usize, hash: impl Fn(&[u8]) -> Vec<u8>, key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut k = if key.len() > block {
        hash(key)
    } else {
        key.to_vec()
    };
    k.resize(block, 0);
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = ipad;
    inner.extend_from_slice(msg);
    let inner_hash = hash(&inner);
    let mut outer = opad;
    outer.extend_from_slice(&inner_hash);
    hash(&outer)
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let v = hmac(SHA256_BLOCK, |d| sha256(d).to_vec(), key, msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

pub fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let v = hmac(SHA1_BLOCK, |d| sha1(d).to_vec(), key, msg);
    let mut out = [0u8; 20];
    out.copy_from_slice(&v);
    out
}

// -- PBKDF2-HMAC-SHA256 -------------------------------------------------------

pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, dklen: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(dklen);
    let mut block_index: u32 = 1;
    while out.len() < dklen {
        let mut salt_block = salt.to_vec();
        salt_block.extend_from_slice(&block_index.to_be_bytes());
        let mut u = hmac_sha256(password, &salt_block);
        let mut t = u;
        for _ in 1..iterations {
            u = hmac_sha256(password, &u);
            for i in 0..32 {
                t[i] ^= u[i];
            }
        }
        out.extend_from_slice(&t);
        block_index += 1;
    }
    out.truncate(dklen);
    out
}

// -- scrypt (RFC 7914) --------------------------------------------------------

fn salsa20_8(block: &mut [u8; 64]) {
    let mut x = [0u32; 16];
    for i in 0..16 {
        x[i] = u32::from_le_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    let input = x;
    macro_rules! r {
        ($a:expr, $b:expr, $c:expr, $n:expr) => {
            x[$a] ^= x[$b].wrapping_add(x[$c]).rotate_left($n);
        };
    }
    for _ in 0..4 {
        // columns
        r!(4, 0, 12, 7);
        r!(8, 4, 0, 9);
        r!(12, 8, 4, 13);
        r!(0, 12, 8, 18);
        r!(9, 5, 1, 7);
        r!(13, 9, 5, 9);
        r!(1, 13, 9, 13);
        r!(5, 1, 13, 18);
        r!(14, 10, 6, 7);
        r!(2, 14, 10, 9);
        r!(6, 2, 14, 13);
        r!(10, 6, 2, 18);
        r!(3, 15, 11, 7);
        r!(7, 3, 15, 9);
        r!(11, 7, 3, 13);
        r!(15, 11, 7, 18);
        // rows
        r!(1, 0, 3, 7);
        r!(2, 1, 0, 9);
        r!(3, 2, 1, 13);
        r!(0, 3, 2, 18);
        r!(6, 5, 4, 7);
        r!(7, 6, 5, 9);
        r!(4, 7, 6, 13);
        r!(5, 4, 7, 18);
        r!(11, 10, 9, 7);
        r!(8, 11, 10, 9);
        r!(9, 8, 11, 13);
        r!(10, 9, 8, 18);
        r!(12, 15, 14, 7);
        r!(13, 12, 15, 9);
        r!(14, 13, 12, 13);
        r!(15, 14, 13, 18);
    }
    for i in 0..16 {
        let v = x[i].wrapping_add(input[i]);
        block[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
}

fn block_mix(b: &[u8], r: usize) -> Vec<u8> {
    let two_r = 2 * r;
    let mut x = [0u8; 64];
    x.copy_from_slice(&b[(two_r - 1) * 64..two_r * 64]);
    let mut y = vec![0u8; b.len()];
    for i in 0..two_r {
        for j in 0..64 {
            x[j] ^= b[i * 64 + j];
        }
        salsa20_8(&mut x);
        // Even i -> first half, odd i -> second half (the Y[0],Y[2],.. order).
        let dest = if i % 2 == 0 {
            (i / 2) * 64
        } else {
            (r + i / 2) * 64
        };
        y[dest..dest + 64].copy_from_slice(&x);
    }
    y
}

fn romix(b: &mut [u8], n: usize, r: usize) {
    let len = 128 * r;
    let mut x = b.to_vec();
    let mut v = vec![0u8; n * len];
    for i in 0..n {
        v[i * len..(i + 1) * len].copy_from_slice(&x);
        x = block_mix(&x, r);
    }
    for _ in 0..n {
        // Integerify: last 64-byte block as a little-endian integer, mod N.
        let j = {
            let last = &x[(2 * r - 1) * 64..];
            u64::from_le_bytes([
                last[0], last[1], last[2], last[3], last[4], last[5], last[6], last[7],
            ]) as usize
                % n
        };
        for k in 0..len {
            x[k] ^= v[j * len + k];
        }
        x = block_mix(&x, r);
    }
    b.copy_from_slice(&x);
}

/// scrypt(password, salt, N, r, p, dklen). N must be a power of two.
pub fn scrypt(password: &[u8], salt: &[u8], n: usize, r: usize, p: usize, dklen: usize) -> Vec<u8> {
    let mut b = pbkdf2_hmac_sha256(password, salt, 1, p * 128 * r);
    let chunk = 128 * r;
    for i in 0..p {
        romix(&mut b[i * chunk..(i + 1) * chunk], n, r);
    }
    pbkdf2_hmac_sha256(password, &b, 1, dklen)
}

// -- constant-time comparison -------------------------------------------------

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::hex;

    #[test]
    fn sha256_vectors() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha1_vectors() {
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn hmac_vectors() {
        // RFC 2202 / RFC 4231 test 1: key = 0x0b*20, data = "Hi There".
        let key = [0x0bu8; 20];
        assert_eq!(
            hex(&hmac_sha1(&key, b"Hi There")),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
        assert_eq!(
            hex(&hmac_sha256(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn scrypt_rfc_vector() {
        // RFC 7914 section 12: scrypt("", "", 16, 1, 1, 64)
        let out = scrypt(b"", b"", 16, 1, 1, 64);
        assert_eq!(
            hex(&out),
            "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442\
             fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"
        );
    }

    #[test]
    fn scrypt_second_vector() {
        // RFC 7914: scrypt("password", "NaCl", 1024, 8, 16, 64)
        let out = scrypt(b"password", b"NaCl", 1024, 8, 16, 64);
        assert_eq!(
            hex(&out),
            "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162\
             2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"
        );
    }

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
