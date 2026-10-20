//! Password hashing, tokens, TOTP and a small in-memory rate limiter. Built on
//! our own crypto/encoding/rand modules (no third-party crates). The password
//! hash format (`scrypt$N$r$p$b64salt$b64digest`) is kept byte-for-byte.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use crate::crypto::{ct_eq, hmac_sha1, scrypt, sha256};
use crate::encoding::{
    base32_decode, base32_encode_nopad, base64_decode, base64_encode, base64url_encode_nopad, hex,
};
use crate::rand;

const SCRYPT_N: usize = 1 << 14; // 16384
const SCRYPT_R: usize = 8;
const SCRYPT_P: usize = 1;
const SCRYPT_LEN: usize = 32;

pub fn hash_password(password: &str) -> String {
    let salt = rand::bytes(16);
    let digest = scrypt(
        password.as_bytes(),
        &salt,
        SCRYPT_N,
        SCRYPT_R,
        SCRYPT_P,
        SCRYPT_LEN,
    );
    format!(
        "scrypt${}${}${}${}${}",
        SCRYPT_N,
        SCRYPT_R,
        SCRYPT_P,
        base64_encode(&salt),
        base64_encode(&digest),
    )
}

pub fn verify_password(password: &str, stored: &str) -> bool {
    let parts: Vec<&str> = stored.split('$').collect();
    if parts.len() != 6 || parts[0] != "scrypt" {
        return false;
    }
    let (Ok(n), Ok(r), Ok(p)) = (
        parts[1].parse::<usize>(),
        parts[2].parse::<usize>(),
        parts[3].parse::<usize>(),
    ) else {
        return false;
    };
    let (Some(salt), Some(expected)) = (base64_decode(parts[4]), base64_decode(parts[5])) else {
        return false;
    };
    if n == 0 || (n & (n - 1)) != 0 {
        return false;
    }
    let actual = scrypt(password.as_bytes(), &salt, n, r, p, expected.len());
    ct_eq(&actual, &expected)
}

/// A hash to verify against when a user does not exist, so a missing account
/// costs the same time as a wrong password.
pub fn dummy_hash() -> &'static str {
    use std::sync::OnceLock;
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| hash_password(&hex(&rand::bytes(8))))
}

pub fn new_token() -> String {
    base64url_encode_nopad(&rand::bytes(32))
}

pub fn token_hash(token: &str) -> String {
    hex(&sha256(token.as_bytes()))
}

// -- TOTP (RFC 6238, SHA-1, 6 digits, 30 s) -----------------------------------

pub fn new_totp_secret() -> String {
    base32_encode_nopad(&rand::bytes(20))
}

fn hotp(secret: &str, counter: u64) -> Option<String> {
    let key = base32_decode(&secret.to_uppercase())?;
    let digest = hmac_sha1(&key, &counter.to_be_bytes());
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let code = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    Some(format!("{:06}", code % 1_000_000))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn totp_now(secret: &str) -> String {
    hotp(secret, now_secs() / 30).unwrap_or_default()
}

pub fn verify_totp(secret: &str, code: &str) -> bool {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if secret.is_empty() || code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let step = (now_secs() / 30) as i64;
    (-1..=1).any(|delta| {
        hotp(secret, (step + delta) as u64)
            .map(|c| ct_eq(c.as_bytes(), code.as_bytes()))
            .unwrap_or(false)
    })
}

pub fn totp_uri(secret: &str, account: &str, issuer: &str) -> String {
    let label = urlencode(&format!("{issuer}:{account}"));
    format!(
        "otpauth://totp/{label}?secret={secret}&issuer={}",
        urlencode(issuer)
    )
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

// -- rate limiter -------------------------------------------------------------

pub struct RateLimiter {
    limit: usize,
    window: f64,
    hits: Mutex<HashMap<String, Vec<Instant>>>,
}

impl RateLimiter {
    pub fn new(limit: usize, window_secs: f64) -> Self {
        RateLimiter {
            limit,
            window: window_secs,
            hits: Mutex::new(HashMap::new()),
        }
    }

    fn prune(&self, map: &mut HashMap<String, Vec<Instant>>, key: &str, now: Instant) -> usize {
        let kept: Vec<Instant> = map
            .get(key)
            .map(|v| {
                v.iter()
                    .copied()
                    .filter(|t| now.duration_since(*t).as_secs_f64() < self.window)
                    .collect()
            })
            .unwrap_or_default();
        if kept.is_empty() {
            map.remove(key);
            0
        } else {
            let n = kept.len();
            map.insert(key.to_string(), kept);
            n
        }
    }

    pub fn blocked(&self, key: &str) -> bool {
        let mut map = self.hits.lock().unwrap();
        self.prune(&mut map, key, Instant::now()) >= self.limit
    }

    pub fn hit(&self, key: &str) {
        let mut map = self.hits.lock().unwrap();
        let now = Instant::now();
        self.prune(&mut map, key, now);
        map.entry(key.to_string()).or_default().push(now);
    }

    pub fn reset(&self, key: &str) {
        self.hits.lock().unwrap().remove(key);
    }
}

// -- 2FA backup codes ---------------------------------------------------------

const BACKUP_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";

pub fn new_backup_codes(count: usize) -> (Vec<String>, Vec<String>) {
    let mut codes = Vec::with_capacity(count);
    for _ in 0..count {
        let pick = |n: usize| {
            rand::bytes(n)
                .iter()
                .map(|b| BACKUP_ALPHABET[*b as usize % BACKUP_ALPHABET.len()] as char)
                .collect::<String>()
        };
        codes.push(format!("{}-{}", pick(4), pick(4)));
    }
    let hashes = codes.iter().map(|c| token_hash(c)).collect();
    (codes, hashes)
}

pub fn match_backup_code(hashes: &[String], code: &str) -> Option<usize> {
    let mut code: String = code
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if code.len() == 8 && !code.contains('-') {
        code = format!("{}-{}", &code[..4], &code[4..]);
    }
    let digest = token_hash(&code);
    hashes
        .iter()
        .position(|h| ct_eq(h.as_bytes(), digest.as_bytes()))
}

pub fn new_email_code() -> String {
    let b = rand::bytes(4);
    let n = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    format!("{:06}", n % 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_round_trip() {
        let h = hash_password("hunter2");
        assert!(verify_password("hunter2", &h));
        assert!(!verify_password("wrong", &h));
        assert!(h.starts_with("scrypt$16384$8$1$"));
    }

    #[test]
    fn totp_matches_itself() {
        let secret = new_totp_secret();
        let code = totp_now(&secret);
        assert!(verify_totp(&secret, &code));
        assert!(!verify_totp(&secret, "000000"));
        assert!(!verify_totp(&secret, "abc"));
    }

    #[test]
    fn totp_known_vector() {
        // RFC 6238 appendix B uses an ASCII secret "12345678901234567890".
        // Base32 of that secret:
        let secret = base32_encode_nopad(b"12345678901234567890");
        // At T=59 (counter=1) the SHA-1 TOTP is 94287082.
        assert_eq!(hotp(&secret, 1).unwrap(), "287082");
    }

    #[test]
    fn backup_codes() {
        let (codes, hashes) = new_backup_codes(6);
        assert_eq!(codes.len(), 6);
        assert_eq!(match_backup_code(&hashes, &codes[2]), Some(2));
        let nodash = codes[2].replace('-', "");
        assert_eq!(match_backup_code(&hashes, &nodash), Some(2));
        assert_eq!(match_backup_code(&hashes, "zzzz-zzzz"), None);
    }

    #[test]
    fn rate_limiter() {
        let rl = RateLimiter::new(3, 100.0);
        rl.hit("ip");
        rl.hit("ip");
        assert!(!rl.blocked("ip"));
        rl.hit("ip");
        assert!(rl.blocked("ip"));
        rl.reset("ip");
        assert!(!rl.blocked("ip"));
    }

    #[test]
    fn tokens() {
        assert!(!new_token().is_empty());
        assert_eq!(token_hash("abc").len(), 64);
    }
}
