"""Account login shared by the RustDesk client and the web console: password
checks, rate limits, login alarms, and the second factor (TOTP, backup code
or an emailed code)."""

import json
import secrets
import threading
import time

from . import mail
from .db import now
from .security import (DUMMY_HASH, RateLimiter, match_backup_code, new_email_code,
                       token_hash, verify_password, verify_totp)

login_failures = RateLimiter(limit=10, window=300)

_pending = {}  # challenge secret -> dict(user_id, method, code_hash, expires, attempts)
_lock = threading.Lock()
_alarm_state = {}  # username -> dict(consecutive, times)


class LoginError(Exception):
    pass


def check_password(app, req, username, password, device_id=""):
    """Return the user row for valid credentials, else raise LoginError."""
    username = (username or "").strip()
    keys = ("ip:" + req.ip, "user:" + username.lower())
    if any(login_failures.blocked(k) for k in keys):
        raise LoginError("Too many failed attempts, try again in a few minutes")
    user = app.db.one("SELECT * FROM users WHERE name = ?", (username,))
    if user is None:
        verify_password(password or "", DUMMY_HASH)
    if user is None or not verify_password(password or "", user["password_hash"]):
        for k in keys:
            login_failures.hit(k)
        _record_failure(app, req, username, device_id)
        raise LoginError("Wrong username or password")
    if user["status"] == -1:
        raise LoginError("This account has not been activated; use the link in the invitation email")
    if user["status"] != 1:
        raise LoginError("User is disabled")
    login_failures.reset("user:" + username.lower())
    _alarm_state.pop(username.lower(), None)
    return user


def _record_failure(app, req, username, device_id):
    """Raise Pro's login-account alarms (types 3, 4 and 5)."""
    if not username:
        return
    t = time.time()
    with _lock:
        state = _alarm_state.setdefault(username.lower(), {"consecutive": 0, "times": []})
        state["consecutive"] += 1
        state["times"] = [x for x in state["times"] if t - x < 3600] + [t]
        minute = sum(1 for x in state["times"] if t - x < 60)
        alarms = []
        if state["consecutive"] == 30:
            alarms.append(3)
        if minute == 5:
            alarms.append(4)
        if len(state["times"]) == 15:
            alarms.append(5)
    for typ in alarms:
        app.db.run("INSERT INTO alarm_logs(device_id, typ, info, ip, created_at) VALUES (?, ?, ?, ?, ?)",
                   (device_id or "", typ, json.dumps({"name": username, "ip": req.ip, "id": device_id or ""}),
                    req.ip, now()))


def second_factor(user):
    """'totp', 'email' or None. TOTP replaces email verification, as in Pro."""
    if user["totp_secret"]:
        return "totp"
    if user["email_verification"] and user["email"]:
        return "email"
    return None


def needs_2fa_setup(user):
    return bool(user["force_2fa"]) and not user["totp_secret"]


def start_challenge(app, user, method):
    """Create a pending second-factor check; email the code if needed."""
    code_hash = ""
    if method == "email":
        code = new_email_code()
        code_hash = token_hash(code)
        mail.send(app.db.settings(), user["email"], "RussDesk login code",
                  f"Your RussDesk login code is {code}\n\nIt expires in 10 minutes. "
                  "If you did not try to log in, change your password.")
    secret = secrets.token_urlsafe(24)
    with _lock:
        _pending[secret] = {"user_id": user["id"], "method": method, "code_hash": code_hash,
                            "expires": time.time() + 600, "attempts": 0}
    return secret


def finish_challenge(app, req, secret, code):
    """Verify a second-factor code for a pending login; return the user."""
    with _lock:
        pending = _pending.get(secret or "")
        if pending is None or pending["expires"] < time.time():
            _pending.pop(secret or "", None)
            raise LoginError("Verification expired, log in again")
        pending["attempts"] += 1
        if pending["attempts"] > 5:
            _pending.pop(secret, None)
            raise LoginError("Too many wrong codes, log in again")
    user = app.db.one("SELECT * FROM users WHERE id = ?", (pending["user_id"],))
    if user is None or user["status"] != 1:
        raise LoginError("User is disabled")
    if pending["method"] == "email":
        ok = bool(code) and secrets.compare_digest(token_hash(code.strip()), pending["code_hash"])
    else:
        ok = verify_code(app.db, user, code)
    if not ok:
        login_failures.hit("user:" + user["name"].lower())
        raise LoginError("Wrong verification code")
    with _lock:
        _pending.pop(secret, None)
    return user


def verify_code(db, user, code):
    """A TOTP code, or one of the user's unused backup codes (consumed)."""
    if verify_totp(user["totp_secret"], code):
        return True
    hashes = json.loads(user["totp_backup"] or "[]")
    i = match_backup_code(hashes, code)
    if i < 0:
        return False
    hashes.pop(i)
    db.run("UPDATE users SET totp_backup = ? WHERE id = ?", (json.dumps(hashes), user["id"]))
    return True


def expire_pending():
    with _lock:
        for secret, p in list(_pending.items()):
            if p["expires"] < time.time():
                _pending.pop(secret, None)
