"""SQLite storage: schema, migrations and small query helpers."""

import json
import os
import sqlite3
import threading
import time
import uuid

SCHEMA_VERSION = 2

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_groups (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE COLLATE NOCASE,
    note       TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS device_groups (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    note        TEXT NOT NULL DEFAULT '',
    strategy_id INTEGER REFERENCES strategies(id) ON DELETE SET NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS strategies (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    note        TEXT NOT NULL DEFAULT '',
    options     TEXT NOT NULL DEFAULT '{}',
    modified_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name  TEXT NOT NULL DEFAULT '',
    email         TEXT NOT NULL DEFAULT '',
    note          TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    status        INTEGER NOT NULL DEFAULT 1,
    group_id      INTEGER REFERENCES user_groups(id) ON DELETE SET NULL,
    strategy_id   INTEGER REFERENCES strategies(id) ON DELETE SET NULL,
    totp_secret   TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL,
    last_login_at INTEGER
);

CREATE TABLE IF NOT EXISTS tokens (
    token_hash   TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL CHECK (kind IN ('client', 'console')),
    device_id    TEXT NOT NULL DEFAULT '',
    device_uuid  TEXT NOT NULL DEFAULT '',
    device_info  TEXT NOT NULL DEFAULT '{}',
    ip           TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS tokens_user ON tokens(user_id);

CREATE TABLE IF NOT EXISTS devices (
    id              TEXT PRIMARY KEY,
    uuid            TEXT NOT NULL DEFAULT '',
    hostname        TEXT NOT NULL DEFAULT '',
    username        TEXT NOT NULL DEFAULT '',
    os              TEXT NOT NULL DEFAULT '',
    cpu             TEXT NOT NULL DEFAULT '',
    memory          TEXT NOT NULL DEFAULT '',
    version         TEXT NOT NULL DEFAULT '',
    sysinfo         TEXT NOT NULL DEFAULT '{}',
    ip              TEXT NOT NULL DEFAULT '',
    note            TEXT NOT NULL DEFAULT '',
    user_id         INTEGER REFERENCES users(id) ON DELETE SET NULL,
    device_group_id INTEGER REFERENCES device_groups(id) ON DELETE SET NULL,
    strategy_id     INTEGER REFERENCES strategies(id) ON DELETE SET NULL,
    -- config keys the last strategy pushed, so they can be cleared when it changes
    applied_keys    TEXT NOT NULL DEFAULT '[]',
    conns           TEXT NOT NULL DEFAULT '[]',
    created_at      INTEGER NOT NULL,
    last_seen_at    INTEGER,
    sysinfo_at      INTEGER
);

CREATE TABLE IF NOT EXISTS pending_disconnects (
    device_id  TEXT NOT NULL,
    conn_id    INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (device_id, conn_id)
);

CREATE TABLE IF NOT EXISTS address_books (
    guid       TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    owner_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    personal   INTEGER NOT NULL DEFAULT 0,
    note       TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ab_personal ON address_books(owner_id) WHERE personal = 1;

CREATE TABLE IF NOT EXISTS ab_rules (
    guid          TEXT NOT NULL REFERENCES address_books(guid) ON DELETE CASCADE,
    user_id       INTEGER REFERENCES users(id) ON DELETE CASCADE,
    user_group_id INTEGER REFERENCES user_groups(id) ON DELETE CASCADE,
    rule          INTEGER NOT NULL CHECK (rule IN (1, 2, 3)),
    CHECK ((user_id IS NULL) <> (user_group_id IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS ab_rules_user ON ab_rules(guid, user_id) WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ab_rules_group ON ab_rules(guid, user_group_id) WHERE user_group_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS ab_peers (
    guid       TEXT NOT NULL REFERENCES address_books(guid) ON DELETE CASCADE,
    peer_id    TEXT NOT NULL,
    alias      TEXT NOT NULL DEFAULT '',
    tags       TEXT NOT NULL DEFAULT '[]',
    hash       TEXT NOT NULL DEFAULT '',
    password   TEXT NOT NULL DEFAULT '',
    username   TEXT NOT NULL DEFAULT '',
    hostname   TEXT NOT NULL DEFAULT '',
    platform   TEXT NOT NULL DEFAULT '',
    note       TEXT NOT NULL DEFAULT '',
    extra      TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL,
    PRIMARY KEY (guid, peer_id)
);

CREATE TABLE IF NOT EXISTS ab_tags (
    guid  TEXT NOT NULL REFERENCES address_books(guid) ON DELETE CASCADE,
    name  TEXT NOT NULL,
    color INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (guid, name)
);

CREATE TABLE IF NOT EXISTS conn_logs (
    id            INTEGER PRIMARY KEY,
    device_id     TEXT NOT NULL,
    conn_id       INTEGER NOT NULL,
    session_id    TEXT NOT NULL DEFAULT '',
    peer_id       TEXT NOT NULL DEFAULT '',
    peer_name     TEXT NOT NULL DEFAULT '',
    ip            TEXT NOT NULL DEFAULT '',
    type          INTEGER,
    primary_auth  INTEGER,
    two_factor    INTEGER,
    started_at    INTEGER NOT NULL,
    authorized_at INTEGER,
    ended_at      INTEGER
);
CREATE INDEX IF NOT EXISTS conn_logs_open ON conn_logs(device_id, conn_id, ended_at);
CREATE INDEX IF NOT EXISTS conn_logs_started ON conn_logs(started_at);

CREATE TABLE IF NOT EXISTS file_logs (
    id         INTEGER PRIMARY KEY,
    device_id  TEXT NOT NULL,
    peer_id    TEXT NOT NULL DEFAULT '',
    conn_id    INTEGER,
    type       INTEGER NOT NULL DEFAULT 0,
    path       TEXT NOT NULL DEFAULT '',
    is_file    INTEGER NOT NULL DEFAULT 0,
    info       TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS file_logs_created ON file_logs(created_at);

CREATE TABLE IF NOT EXISTS alarm_logs (
    id         INTEGER PRIMARY KEY,
    device_id  TEXT NOT NULL,
    typ        INTEGER NOT NULL,
    info       TEXT NOT NULL DEFAULT '{}',
    conn_id    INTEGER,
    ip         TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS alarm_logs_created ON alarm_logs(created_at);

CREATE TABLE IF NOT EXISTS console_logs (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER,
    user_name  TEXT NOT NULL DEFAULT '',
    action     TEXT NOT NULL,
    target     TEXT NOT NULL DEFAULT '',
    detail     TEXT NOT NULL DEFAULT '',
    ip         TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS console_logs_created ON console_logs(created_at);

CREATE TABLE IF NOT EXISTS nonces (
    nonce      TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS recordings (
    id           INTEGER PRIMARY KEY,
    filename     TEXT NOT NULL UNIQUE,
    size         INTEGER NOT NULL DEFAULT 0,
    ip           TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    completed_at INTEGER
);
"""

# Console-editable settings and their defaults.
DEFAULT_SETTINGS = {
    "id_server": "",
    "relay_server": "",
    "api_server": "",
    "server_key": "",
    "client_token_days": 0,  # 0 = client logins never expire
    "console_session_hours": 12,
    "log_retention_days": 180,
    "accept_recordings": False,
    "recordings_max_mb": 10240,
    "max_peers_per_ab": 0,
    "default_strategy_id": None,
    # Settings > Others, as in Pro
    "only_admin_logs": False,
    "allow_non_admin_share": False,
    "disable_accessible_devices": False,
    "console_url": "",
    # Settings > SMTP
    "smtp_host": "",
    "smtp_port": 587,
    "smtp_security": "starttls",  # starttls | ssl | none
    "smtp_user": "",
    "smtp_password": "",
    "smtp_from": "",
}

# Applied in order to bring an older database up to SCHEMA_VERSION. The v1
# SCHEMA above always runs first, so a fresh database goes through them too.
V2_COLUMNS = [
    ("users", "guid", "TEXT"),
    ("users", "email_verification", "INTEGER NOT NULL DEFAULT 0"),
    ("users", "force_2fa", "INTEGER NOT NULL DEFAULT 0"),
    ("users", "totp_backup", "TEXT NOT NULL DEFAULT '[]'"),
    ("users", "totp_set_at", "INTEGER"),
    ("users", "invite_hash", "TEXT NOT NULL DEFAULT ''"),
    ("users", "invite_expires", "INTEGER"),
    ("user_groups", "guid", "TEXT"),
    ("device_groups", "guid", "TEXT"),
    ("strategies", "guid", "TEXT"),
    ("strategies", "enabled", "INTEGER NOT NULL DEFAULT 1"),
    ("devices", "guid", "TEXT"),
    ("devices", "disabled", "INTEGER NOT NULL DEFAULT 0"),
    ("devices", "name_override", "TEXT NOT NULL DEFAULT ''"),
    ("devices", "username_override", "TEXT NOT NULL DEFAULT ''"),
    ("address_books", "password", "TEXT NOT NULL DEFAULT ''"),
    ("ab_peers", "deleted_at", "INTEGER"),
    ("conn_logs", "note", "TEXT NOT NULL DEFAULT ''"),
    ("conn_logs", "controller", "TEXT NOT NULL DEFAULT ''"),
    ("console_logs", "typ", "INTEGER"),
    ("console_logs", "iop", "INTEGER"),
]

V2_TABLES = """
-- Who can see what: a user or user group may access a user group's users'
-- devices or a device group's devices. Pro's "access to" / "accessed from".
CREATE TABLE IF NOT EXISTS access_rules (
    subject_type TEXT NOT NULL CHECK (subject_type IN ('user', 'user_group')),
    subject_id   INTEGER NOT NULL,
    target_type  TEXT NOT NULL CHECK (target_type IN ('user_group', 'device_group')),
    target_id    INTEGER NOT NULL,
    PRIMARY KEY (subject_type, subject_id, target_type, target_id)
);
CREATE INDEX IF NOT EXISTS access_rules_target ON access_rules(target_type, target_id);

CREATE TABLE IF NOT EXISTS api_tokens (
    id           INTEGER PRIMARY KEY,
    guid         TEXT NOT NULL UNIQUE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    user_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,
    perms        TEXT NOT NULL DEFAULT '{}',
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER,
    last_used_at INTEGER
);

CREATE TABLE IF NOT EXISTS admin_roles (
    id            INTEGER PRIMARY KEY,
    guid          TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL UNIQUE COLLATE NOCASE,
    type          TEXT NOT NULL CHECK (type IN ('global', 'individual', 'group')),
    perms         TEXT NOT NULL DEFAULT '[]',
    user_groups   TEXT NOT NULL DEFAULT '[]',
    device_groups TEXT NOT NULL DEFAULT '[]',
    unassigned    INTEGER NOT NULL DEFAULT 0,
    note          TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_admin_roles (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES admin_roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- Shared address book rules: a user, a user group, or everyone.
CREATE TABLE IF NOT EXISTS ab_rules2 (
    id            INTEGER PRIMARY KEY,
    rule_guid     TEXT NOT NULL UNIQUE,
    guid          TEXT NOT NULL REFERENCES address_books(guid) ON DELETE CASCADE,
    user_id       INTEGER REFERENCES users(id) ON DELETE CASCADE,
    user_group_id INTEGER REFERENCES user_groups(id) ON DELETE CASCADE,
    everyone      INTEGER NOT NULL DEFAULT 0,
    rule          INTEGER NOT NULL CHECK (rule IN (1, 2, 3))
);
"""


def _columns(c, table):
    return {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}


def migrate_v2(c):
    for table, column, decl in V2_COLUMNS:
        if column not in _columns(c, table):
            c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
    for statement in _statements(V2_TABLES):
        c.execute(statement)
    for table in ("users", "user_groups", "device_groups", "strategies", "devices"):
        for row in c.execute(f"SELECT rowid FROM {table} WHERE guid IS NULL").fetchall():
            c.execute(f"UPDATE {table} SET guid = ? WHERE rowid = ?", (str(uuid.uuid4()), row[0]))
        c.execute(f"CREATE UNIQUE INDEX IF NOT EXISTS {table}_guid ON {table}(guid)")
    # Move v1 group access and address book rules to their v2 tables.
    if "group_access" in _tables(c):
        c.execute("INSERT OR IGNORE INTO access_rules(subject_type, subject_id, target_type, target_id) "
                  "SELECT 'user_group', user_group_id, target_type, target_id FROM group_access")
        c.execute("DROP TABLE group_access")
    if "rule" in _columns(c, "ab_rules") and "rule_guid" not in _columns(c, "ab_rules"):
        for r in c.execute("SELECT * FROM ab_rules").fetchall():
            c.execute("INSERT INTO ab_rules2(rule_guid, guid, user_id, user_group_id, everyone, rule) "
                      "VALUES (?, ?, ?, ?, 0, ?)",
                      (str(uuid.uuid4()), r["guid"], r["user_id"], r["user_group_id"], r["rule"]))
        c.execute("DROP TABLE ab_rules")
    if "ab_rules2" in _tables(c):
        c.execute("ALTER TABLE ab_rules2 RENAME TO ab_rules")
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ab_rules_user ON ab_rules(guid, user_id) WHERE user_id IS NOT NULL")
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ab_rules_group ON ab_rules(guid, user_group_id) "
              "WHERE user_group_id IS NOT NULL")
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ab_rules_everyone ON ab_rules(guid) WHERE everyone = 1")


def _tables(c):
    return {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _statements(script):
    """Split a script of CREATE statements; executescript() would commit."""
    return [s.strip() for s in script.split(";") if "CREATE" in s]


MIGRATIONS = {2: migrate_v2}


def now():
    return int(time.time())


class Database:
    def __init__(self, path):
        self.path = path
        self._local = threading.local()
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        self.migrate()

    def conn(self):
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA foreign_keys = ON")
            c.execute("PRAGMA journal_mode = WAL")
            c.execute("PRAGMA synchronous = NORMAL")
            c.execute("PRAGMA busy_timeout = 30000")
            self._local.conn = c
        return c

    def close(self):
        c = getattr(self._local, "conn", None)
        if c is not None:
            c.close()
            self._local.conn = None

    def migrate(self):
        c = self.conn()
        c.executescript(SCHEMA)
        row = c.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
        if row is None:
            c.execute("INSERT INTO meta(key, value) VALUES ('schema_version', '1'), ('instance_id', ?)",
                      (uuid.uuid4().hex,))
            version = 1
        else:
            version = int(row["value"])
        while version < SCHEMA_VERSION:
            version += 1
            c.execute("PRAGMA foreign_keys = OFF")  # table rebuilds
            try:
                with self.tx() as t:
                    MIGRATIONS[version](t)
                    t.execute("UPDATE meta SET value = ? WHERE key = 'schema_version'", (str(version),))
            finally:
                c.execute("PRAGMA foreign_keys = ON")

    # -- helpers -----------------------------------------------------------

    def one(self, sql, params=()):
        return self.conn().execute(sql, params).fetchone()

    def all(self, sql, params=()):
        return self.conn().execute(sql, params).fetchall()

    def run(self, sql, params=()):
        return self.conn().execute(sql, params)

    def tx(self):
        return _Transaction(self.conn())

    def meta(self, key):
        row = self.one("SELECT value FROM meta WHERE key = ?", (key,))
        return row["value"] if row else None

    def settings(self):
        values = dict(DEFAULT_SETTINGS)
        for row in self.all("SELECT key, value FROM settings"):
            if row["key"] in values:
                values[row["key"]] = json.loads(row["value"])
        return values

    def setting(self, key):
        return self.settings()[key]

    def set_settings(self, values):
        with self.tx() as c:
            for key, value in values.items():
                if key not in DEFAULT_SETTINGS:
                    raise KeyError(key)
                c.execute(
                    "INSERT INTO settings(key, value) VALUES (?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, json.dumps(value)),
                )


class _Transaction:
    def __init__(self, conn):
        self.c = conn

    def __enter__(self):
        self.c.execute("BEGIN IMMEDIATE")
        return self.c

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.c.execute("COMMIT")
        else:
            self.c.execute("ROLLBACK")
        return False
