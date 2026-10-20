//! Base64, Base32 and hex, std-only. RFC 4648.

const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn b64_encode(data: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(alphabet[(n >> 18) as usize & 63] as char);
        out.push(alphabet[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(alphabet[(n >> 6) as usize & 63] as char);
        } else if pad {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(alphabet[n as usize & 63] as char);
        } else if pad {
            out.push('=');
        }
    }
    out
}

fn b64_decode(s: &str, alphabet: &[u8; 64]) -> Option<Vec<u8>> {
    let mut rev = [255u8; 256];
    for (i, &c) in alphabet.iter().enumerate() {
        rev[c as usize] = i as u8;
    }
    let mut bits: u32 = 0;
    let mut nbits = 0u32;
    let mut out = Vec::new();
    for &c in s.as_bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' {
            continue;
        }
        let v = rev[c as usize];
        if v == 255 {
            return None;
        }
        bits = (bits << 6) | v as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    Some(out)
}

pub fn base64_encode(data: &[u8]) -> String {
    b64_encode(data, B64_STD, true)
}
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    b64_decode(s, B64_STD)
}
pub fn base64url_encode_nopad(data: &[u8]) -> String {
    b64_encode(data, B64_URL, false)
}

/// Base32 (RFC 4648) without padding, uppercase.
pub fn base32_encode_nopad(data: &[u8]) -> String {
    let mut out = String::new();
    let mut bits: u32 = 0;
    let mut nbits = 0u32;
    for &b in data {
        bits = (bits << 8) | b as u32;
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(B32[(bits >> nbits) as usize & 31] as char);
        }
    }
    if nbits > 0 {
        out.push(B32[(bits << (5 - nbits)) as usize & 31] as char);
    }
    out
}

pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut rev = [255u8; 256];
    for (i, &c) in B32.iter().enumerate() {
        rev[c as usize] = i as u8;
        rev[c.to_ascii_lowercase() as usize] = i as u8;
    }
    let mut bits: u32 = 0;
    let mut nbits = 0u32;
    let mut out = Vec::new();
    for &c in s.as_bytes() {
        if c == b'=' {
            continue;
        }
        let v = rev[c as usize];
        if v == 255 {
            return None;
        }
        bits = (bits << 5) | v as u32;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    Some(out)
}

pub fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_decode("Zm9vYmFy").unwrap(), b"foobar");
        assert_eq!(base64_decode("Zm8=").unwrap(), b"fo");
        assert!(base64_decode("not base64 @@@").is_none());
    }

    #[test]
    fn base32_round_trip() {
        for v in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            let e = base32_encode_nopad(v);
            assert_eq!(base32_decode(&e).unwrap(), v);
        }
        // RFC 4648 vector
        assert_eq!(base32_encode_nopad(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn hex_vector() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff, 0xa5]), "000fffa5");
    }
}
