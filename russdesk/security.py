"""Password hashing, tokens, TOTP and a small in-memory rate limiter."""

import base64
import hashlib
import hmac
import secrets
import struct
import threading
import time

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2 ** 14, 8, 1


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32
    )
    return "scrypt${}${}${}${}${}".format(
        _SCRYPT_N, _SCRYPT_R, _SCRYPT_P,
        base64.b64encode(salt).decode(), base64.b64encode(digest).decode(),
    )


def verify_password(password, stored):
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(digest)
        actual = hashlib.scrypt(
            password.encode(), salt=base64.b64decode(salt),
            n=int(n), r=int(r), p=int(p), dklen=len(expected),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


# A hash to verify against when the user does not exist, so a missing account
# costs the same time as a wrong password.
DUMMY_HASH = hash_password(secrets.token_hex(8))


def new_token():
    return secrets.token_urlsafe(32)


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


# -- TOTP (RFC 6238, SHA-1, 6 digits, 30 s) -----------------------------------

def new_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret, counter):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return "%06d" % (code % 1000000)


def totp_now(secret, at=None):
    return _hotp(secret, int((time.time() if at is None else at) // 30))


def verify_totp(secret, code, at=None, window=1):
    code = (code or "").strip().replace(" ", "")
    if not secret or len(code) != 6 or not code.isdigit():
        return False
    step = int((time.time() if at is None else at) // 30)
    return any(
        hmac.compare_digest(_hotp(secret, step + delta), code)
        for delta in range(-window, window + 1)
    )


def totp_uri(secret, account, issuer="RussDesk"):
    from urllib.parse import quote
    label = quote(f"{issuer}:{account}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"


class RateLimiter:
    """Counts failures per key inside a sliding window."""

    def __init__(self, limit, window):
        self.limit = limit
        self.window = window
        self._hits = {}
        self._lock = threading.Lock()

    def _prune(self, key, now):
        hits = [t for t in self._hits.get(key, []) if now - t < self.window]
        if hits:
            self._hits[key] = hits
        else:
            self._hits.pop(key, None)
        return hits

    def blocked(self, key):
        with self._lock:
            return len(self._prune(key, time.monotonic())) >= self.limit

    def hit(self, key):
        with self._lock:
            now = time.monotonic()
            self._prune(key, now)
            self._hits.setdefault(key, []).append(now)

    def reset(self, key):
        with self._lock:
            self._hits.pop(key, None)
