"""Application wiring: routing, static files, maintenance and startup."""

import logging
import mimetypes
import os
import secrets
import sqlite3
import threading
import time
import traceback

from . import admin_api, client_api
from .config import Config
from .db import Database, now
from .models import personal_book
from .security import hash_password
from .web import HTTPError, Response, Server, error_response, make_handler

log = logging.getLogger("russdesk")

RECORD_BODY_LIMIT = 256 * 1024 * 1024

CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


class App:
    def __init__(self, cfg=None):
        self.cfg = cfg or Config.from_env()
        self.db = Database(self.cfg.db_path)
        self.routers = [client_api.router, admin_api.router]
        self.common_headers = [
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
        ]
        self._stop = threading.Event()
        self.bootstrap_admin()

    # -- setup -----------------------------------------------------------------

    def bootstrap_admin(self):
        if self.db.one("SELECT 1 FROM users LIMIT 1"):
            return
        password = self.cfg.admin_password
        generated = not password
        if generated:
            password = secrets.token_urlsafe(12)
        cur = self.db.run(
            "INSERT INTO users(name, password_hash, is_admin, status, created_at) VALUES (?, ?, 1, 1, ?)",
            (self.cfg.admin_user, hash_password(password), now()),
        )
        personal_book(self.db, cur.lastrowid)
        if generated:
            # Printed once so the first login is possible; change it afterwards.
            log.warning("Created administrator %r with password: %s", self.cfg.admin_user, password)
        else:
            log.warning("Created administrator %r from RUSSDESK_ADMIN_PASSWORD", self.cfg.admin_user)

    def body_limit(self, path):
        return RECORD_BODY_LIMIT if path.startswith("/api/record") else 2 * 1024 * 1024

    # -- request handling ------------------------------------------------------

    def handle(self, req):
        try:
            if req.path.startswith("/api/"):
                return self.route(req)
            if req.method not in ("GET", "HEAD"):
                raise HTTPError(405, "Method not allowed")
            return self.static(req.path)
        except HTTPError as exc:
            return error_response(exc.status, exc.message)
        except sqlite3.OperationalError as exc:
            log.error("database error on %s %s: %s", req.method, req.path, exc)
            return error_response(503, "Database busy, try again")
        except Exception:
            log.error("error on %s %s\n%s", req.method, req.path, traceback.format_exc())
            return error_response(500, "Internal server error")

    def route(self, req):
        for router in self.routers:
            handler, params = router.match(req.method, req.path)
            if handler is not None:
                resp = handler(self, req, **params)
                resp.headers.append(("Cache-Control", "no-store"))
                return resp
        raise HTTPError(404, "Not found")

    def static(self, path):
        root = os.path.realpath(self.cfg.static_dir)
        rel = path.lstrip("/") or "index.html"
        full = os.path.realpath(os.path.join(root, rel))
        if not full.startswith(root + os.sep) or not os.path.isfile(full):
            # Single-page app: unknown paths get the shell.
            full = os.path.join(root, "index.html")
        with open(full, "rb") as f:
            data = f.read()
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript",):
            ctype += "; charset=utf-8"
        headers = [("Cache-Control", "no-cache")]
        if full.endswith(".html"):
            headers += [("Content-Security-Policy", CSP), ("X-Frame-Options", "DENY")]
        return Response(data, 200, ctype, headers)

    def log_access(self, ip, message):
        log.debug("%s %s", ip, message)

    # -- maintenance -----------------------------------------------------------

    def maintenance(self):
        db = self.db
        db.run("DELETE FROM nonces WHERE created_at < ?", (now() - 600,))
        db.run("DELETE FROM tokens WHERE expires_at < ?", (now(),))
        db.run("DELETE FROM pending_disconnects WHERE created_at < ?", (now() - 300,))
        days = db.setting("log_retention_days")
        if days:
            cutoff = now() - days * 86400
            for table, column in (("conn_logs", "started_at"), ("file_logs", "created_at"),
                                  ("alarm_logs", "created_at"), ("console_logs", "created_at")):
                db.run(f"DELETE FROM {table} WHERE {column} < ?", (cutoff,))
        with client_api._pending_lock:
            for secret, (_, expires, _) in list(client_api._pending_2fa.items()):
                if expires < time.time():
                    client_api._pending_2fa.pop(secret, None)

    def _maintenance_loop(self):
        while not self._stop.wait(300):
            try:
                self.maintenance()
            except Exception:
                log.error("maintenance failed\n%s", traceback.format_exc())

    def serve(self, ready=None):
        server = Server((self.cfg.host, self.cfg.port), make_handler(self))
        self.server = server
        threading.Thread(target=self._maintenance_loop, daemon=True).start()
        log.info("RussDesk listening on http://%s:%d", self.cfg.host, server.server_address[1])
        if ready:
            ready(server)
        try:
            server.serve_forever(poll_interval=0.5)
        finally:
            server.server_close()

    def shutdown(self):
        self._stop.set()
        if getattr(self, "server", None):
            self.server.shutdown()
