"""A minimal request/response layer over http.server."""

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

MAX_BODY = 2 * 1024 * 1024


class HTTPError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


class Request:
    def __init__(self, method, target, headers, body, ip, scheme):
        parts = urlsplit(target)
        self.method = method
        self.path = parts.path
        self.query = {k: v[0] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}
        self.headers = headers
        self.body = body
        self.ip = ip
        self.scheme = scheme
        self.user = None
        self.token = None
        self.actor = None

    def json(self, default=None):
        """Parse the body as JSON whatever the Content-Type (the client
        posts JSON as text/plain)."""
        if not self.body:
            return default
        try:
            return json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise HTTPError(400, "Invalid JSON body")

    def json_object(self):
        data = self.json({})
        if not isinstance(data, dict):
            raise HTTPError(400, "Expected a JSON object")
        return data

    def cookie(self, name):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            key, _, value = part.strip().partition("=")
            if key == name:
                return value
        return None

    def bearer(self):
        auth = self.headers.get("Authorization", "")
        if auth[:7].lower() == "bearer ":
            return auth[7:].strip()
        return None


class Response:
    def __init__(self, body=b"", status=200, content_type="application/json", headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.body = body
        self.status = status
        self.content_type = content_type
        self.headers = list(headers or [])
        self.stream = None  # optional file object streamed after headers
        self.stream_length = 0


def json_response(obj, status=200, headers=None):
    return Response(json.dumps(obj, separators=(",", ":")), status, headers=headers)


def error_response(status, message):
    return json_response({"error": message}, status)


class Router:
    def __init__(self):
        self._routes = []

    def add(self, method, pattern, handler):
        regex = re.compile("^" + re.sub(r"<(\w+)>", r"(?P<\1>[^/]+)", pattern) + "$")
        self._routes.append((method, regex, handler))

    def route(self, method, pattern):
        def decorator(fn):
            self.add(method, pattern, fn)
            return fn
        return decorator

    def match(self, method, path):
        """(handler, params) for a route, or (None, known) where known says
        whether the path exists here with another method."""
        known = False
        for m, regex, handler in self._routes:
            found = regex.match(path)
            if found:
                if m == method:
                    return handler, found.groupdict()
                known = True
        return None, known


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        server_version = "russdesk"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def _client_ip(self):
            ip = self.client_address[0]
            if app.cfg.trust_proxy:
                forwarded = self.headers.get("X-Forwarded-For", "")
                if forwarded:
                    ip = forwarded.split(",")[0].strip()
                else:
                    ip = self.headers.get("X-Real-IP", ip)
            if ip.startswith("::ffff:"):
                ip = ip[7:]
            return ip

        def _scheme(self):
            if app.cfg.trust_proxy:
                return self.headers.get("X-Forwarded-Proto", "http").split(",")[0].strip()
            return "http"

        def _dispatch(self):
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1
            limit = app.body_limit(self.path)
            if length < 0 or length > limit:
                self.close_connection = True
                self._send(error_response(413, "Request body too large"))
                return
            body = self.rfile.read(length) if length else b""
            req = Request(self.command, self.path, self.headers, body,
                          self._client_ip(), self._scheme())
            self._send(app.handle(req), head=self.command == "HEAD")

        def _send(self, resp, head=False):
            self.send_response(resp.status)
            self.send_header("Content-Type", resp.content_type)
            length = len(resp.body) if resp.stream is None else resp.stream_length
            self.send_header("Content-Length", str(length))
            for key, value in app.common_headers + resp.headers:
                self.send_header(key, value)
            self.end_headers()
            if head:
                return
            if resp.stream is not None:
                with resp.stream as f:
                    while True:
                        chunk = f.read(64 * 1024)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
            else:
                self.wfile.write(resp.body)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _dispatch

        def log_message(self, fmt, *args):
            app.log_access(self._client_ip(), fmt % args)

    return Handler


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128
