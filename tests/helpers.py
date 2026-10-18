import json
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from russdesk import client_api
from russdesk.app import App
from russdesk.config import Config

ADMIN_PASSWORD = "admin-pass-123"


class Reply:
    def __init__(self, status, body, headers):
        self.status = status
        self.body = body
        self.headers = headers

    @property
    def text(self):
        return self.body.decode()

    def json(self):
        return json.loads(self.body)


class ServerTest(unittest.TestCase):
    def setUp(self):
        client_api.login_failures._hits.clear()
        self.tmp = tempfile.mkdtemp(prefix="russdesk-test-")
        cfg = Config(data_dir=self.tmp, host="127.0.0.1", port=0,
                     admin_user="admin", admin_password=ADMIN_PASSWORD)
        self.app = App(cfg)
        started = threading.Event()
        self.thread = threading.Thread(
            target=self.app.serve, kwargs={"ready": lambda s: started.set()}, daemon=True)
        self.thread.start()
        started.wait(5)
        self.base = "http://127.0.0.1:%d" % self.app.server.server_address[1]
        self.cookie = None

    def tearDown(self):
        self.app.shutdown()
        self.thread.join(5)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def request(self, method, path, body=None, token=None, raw=None, headers=None, console=False):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if token:
            req.add_header("Authorization", "Bearer " + token)
        if console:
            req.add_header("X-Russdesk", "1")
            if self.cookie:
                req.add_header("Cookie", self.cookie)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                reply = Reply(resp.status, resp.read(), resp.headers)
        except urllib.error.HTTPError as err:
            reply = Reply(err.code, err.read(), err.headers)
        if console and reply.headers.get("Set-Cookie"):
            self.cookie = reply.headers["Set-Cookie"].split(";")[0]
        return reply

    # The RustDesk client posts JSON without a Content-Type header.
    def client(self, method, path, body=None, token=None, raw=None):
        return self.request(method, path, body, token, raw)

    def console(self, method, path, body=None):
        return self.request(method, path, body if body is not None or method == "GET" else {},
                            console=True)

    def console_login(self, username="admin", password=ADMIN_PASSWORD):
        reply = self.console("POST", "/api/admin/login", {"username": username, "password": password})
        self.assertEqual(reply.status, 200, reply.text)
        return reply

    def client_login(self, username="admin", password=ADMIN_PASSWORD, device="123456789", uuid=None):
        reply = self.client("POST", "/api/login", {
            "username": username, "password": password, "id": device, "uuid": uuid or "uuid-" + device,
            "autoLogin": True, "type": "account",
            "deviceInfo": {"os": "linux", "type": "client", "name": "box"},
        })
        self.assertEqual(reply.status, 200, reply.text)
        data = reply.json()
        self.assertEqual(data.get("type"), "access_token", data)
        return data["access_token"]
