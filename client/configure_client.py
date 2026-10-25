#!/usr/bin/env python3
"""Bake self-hosted server settings into the RustDesk client before building.

RustDesk reads its default ID (rendezvous) server and the server's public key
from two compile-time constants in ``libs/hbb_common/src/config.rs``:

    pub const RENDEZVOUS_SERVERS: &[&str] = &["rs-ny.rustdesk.com"];
    pub const RS_PUB_KEY: &str = "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw=";

Patching these two is the documented, version-stable way to hardcode a custom
server, so the shipped .exe/.apk connects to your own hbbs with no manual
Settings -> Network step. The relay server is normally handed to clients by hbbs
at connect time; when you want an explicit default we seed it (and an optional
api-server) into the compile-time ``DEFAULT_SETTINGS`` map.

With ``--password`` it also bakes unattended access: a shared permanent password
(seeded as its hash into ``HARD_SETTINGS`` -- RustDesk's preset-password slot)
plus ``approve-mode=password`` and ``verification-method=use-permanent-password``
in ``DEFAULT_SETTINGS``, so the console/viewer can connect without the remote
user clicking accept or reading out a temporary password.

This module is import-safe (the patch functions are pure string transforms, so
they are unit-tested without a Rust toolchain) and runs as a CLI:

    python3 configure_client.py --id-server rd.example.com:21116 \\
        --key 'BASE64KEY=' --relay rd.example.com:21117

It edits the constants in place and is idempotent: re-running with new values
overwrites the previous ones, so no clean checkout is needed between builds.
"""

import argparse
import base64
import hashlib
import os
import re
import secrets
import sys

# config.rs inside the vendored client, relative to this file.
DEFAULT_CONFIG_RS = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "vendor", "libs", "hbb_common", "src", "config.rs",
)

# A value baked into a Rust string/identifier list. We forbid anything that
# could break out of the "..." literal or inject code: quotes, backslashes and
# control characters. Everything a host:port, URL or base64 key needs is allowed.
_SAFE = re.compile(r'^[A-Za-z0-9._:/\-\[\]+=@]+$')

_RENDEZVOUS_RE = re.compile(r'(?m)^pub const RENDEZVOUS_SERVERS: &\[&str\] = &\[.*\];[ \t]*$')
_PUBKEY_RE = re.compile(r'(?m)^pub const RS_PUB_KEY: &str = ".*";[ \t]*$')
_DEFAULTS_RE = re.compile(
    r'(?m)^(?P<indent>[ \t]*)pub static ref DEFAULT_SETTINGS: '
    r'RwLock<HashMap<String, String>> = .*;[ \t]*$')
_HARD_RE = re.compile(
    r'(?m)^(?P<indent>[ \t]*)pub static ref HARD_SETTINGS: '
    r'RwLock<HashMap<String, String>> = .*;[ \t]*$')


def _preset_password_storage(password):
    """Return (storage, salt) for RustDesk's preset permanent password.

    Mirrors hbb_common's permanent_password.rs: the preset storage is
    "00" + base64(SHA256(password || salt)); the salt is any string. The client
    uses this as the unattended permanent password when none is set locally, so
    the plaintext never has to ship -- only this hash does.
    """
    salt = secrets.token_hex(16)  # 32 chars, DEFAULT_SALT_LEN
    h1 = hashlib.sha256(password.encode("utf-8") + salt.encode("utf-8")).digest()
    storage = "00" + base64.b64encode(h1).decode("ascii")
    return storage, salt


def _check(name, value, *, required):
    """Validate a baked value, returning the stripped string or ""."""
    value = (value or "").strip()
    if not value:
        if required:
            raise ValueError(f"{name} is required")
        return ""
    if not _SAFE.match(value):
        raise ValueError(
            f"{name} contains characters that are not safe to embed: {value!r}")
    return value


def _sub_once(pattern, replacement, text, what):
    new, n = pattern.subn(lambda _m: replacement, text)
    if n != 1:
        raise ValueError(
            f"expected exactly one {what} line to patch, found {n}; the client "
            "source may be a different RustDesk version than this tool targets")
    return new


def _map_decl(indent, name, pairs):
    """Render `pub static ref <name>: RwLock<HashMap<String, String>> = ...;`."""
    if not pairs:
        value = "Default::default()"
    else:
        entries = ", ".join(f'("{k}".to_string(), "{v}".to_string())' for k, v in pairs)
        value = f"RwLock::new(std::collections::HashMap::from([{entries}]))"
    return f"{indent}pub static ref {name}: RwLock<HashMap<String, String>> = {value};"


def _defaults_line(indent, relay, api, unattended):
    pairs = []
    if relay:
        pairs.append(("relay-server", relay))
    if api:
        pairs.append(("api-server", api))
    if unattended:
        # Accept incoming sessions on the permanent password alone -- no "accept"
        # click and no rotating temporary password on the controlled side.
        pairs.append(("approve-mode", "password"))
        pairs.append(("verification-method", "use-permanent-password"))
    return _map_decl(indent, "DEFAULT_SETTINGS", pairs)


def patch_config_rs(text, *, id_server, key, relay="", api="", password=""):
    """Return config.rs source with the server constants baked in.

    Pure function over the file text so it can be tested without Rust. Raises
    ValueError on invalid input or if the expected lines are not found exactly
    once. A non-empty ``password`` bakes a shared unattended permanent password
    (its SHA256 hash, never the plaintext) plus the approve-mode /
    verification-method defaults that let the console connect without the remote
    user accepting.
    """
    id_server = _check("id-server", id_server, required=True)
    key = _check("key", key, required=True)
    relay = _check("relay-server", relay, required=False)
    api = _check("api-server", api, required=False)
    password = (password or "").strip()

    text = _sub_once(
        _RENDEZVOUS_RE,
        f'pub const RENDEZVOUS_SERVERS: &[&str] = &["{id_server}"];',
        text, "RENDEZVOUS_SERVERS")
    text = _sub_once(
        _PUBKEY_RE,
        f'pub const RS_PUB_KEY: &str = "{key}";',
        text, "RS_PUB_KEY")

    match = _DEFAULTS_RE.search(text)
    if match is None:
        raise ValueError("could not find the DEFAULT_SETTINGS declaration")
    text = _sub_once(
        _DEFAULTS_RE,
        _defaults_line(match.group("indent"), relay, api, unattended=bool(password)),
        text, "DEFAULT_SETTINGS")

    if password:
        storage, salt = _preset_password_storage(password)
        match = _HARD_RE.search(text)
        if match is None:
            raise ValueError("could not find the HARD_SETTINGS declaration")
        text = _sub_once(
            _HARD_RE,
            _map_decl(match.group("indent"), "HARD_SETTINGS",
                      [("password", storage), ("salt", salt)]),
            text, "HARD_SETTINGS")
    return text


def configure(path, *, id_server, key, relay="", api="", password="", dry_run=False):
    with open(path, "r", encoding="utf-8") as f:
        original = f.read()
    patched = patch_config_rs(original, id_server=id_server, key=key, relay=relay,
                              api=api, password=password)
    if not dry_run:
        with open(path, "w", encoding="utf-8") as f:
            f.write(patched)
    return patched


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="configure_client.py",
        description="Bake id/relay server and key into the RustDesk client before building")
    p.add_argument("--id-server", default=os.environ.get("RENDEZVOUS_SERVER", ""),
                   help="ID/rendezvous server, host or host:port (env RENDEZVOUS_SERVER)")
    p.add_argument("--key", default=os.environ.get("RS_PUB_KEY", ""),
                   help="server public key, the content of hbbs' id_ed25519.pub (env RS_PUB_KEY)")
    p.add_argument("--relay", default=os.environ.get("RELAY_SERVER", ""),
                   help="optional default relay server; hbbs also advertises one (env RELAY_SERVER)")
    p.add_argument("--api-server", default=os.environ.get("API_SERVER", ""),
                   help="optional default API server, e.g. https://rd.example.com (env API_SERVER)")
    p.add_argument("--password", default=os.environ.get("UNATTENDED_PASSWORD", ""),
                   help="shared permanent password for unattended access; bakes approve-mode / "
                        "verification-method so the console connects without the remote user "
                        "accepting (env UNATTENDED_PASSWORD). Only its SHA256 hash is embedded.")
    p.add_argument("--config-rs", default=DEFAULT_CONFIG_RS,
                   help="path to the client's libs/hbb_common/src/config.rs")
    p.add_argument("--check", action="store_true",
                   help="validate and print the result without writing")
    args = p.parse_args(argv)

    try:
        patched = configure(args.config_rs, id_server=args.id_server, key=args.key,
                            relay=args.relay, api=args.api_server, password=args.password,
                            dry_run=args.check)
    except (ValueError, OSError) as exc:
        sys.exit(f"configure_client: {exc}")

    for line in patched.splitlines():
        if line.startswith("pub const RENDEZVOUS_SERVERS") or line.startswith("pub const RS_PUB_KEY") \
                or "DEFAULT_SETTINGS:" in line or "HARD_SETTINGS:" in line:
            print(("would set " if args.check else "set ") + line.strip())


if __name__ == "__main__":
    main()
