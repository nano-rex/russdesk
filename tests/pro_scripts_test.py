"""Run RustDesk Server Pro's own management scripts (rustdesk/rustdesk res/*.py,
unmodified) against RussDesk. Needs the `requests` package and network access
to fetch the scripts, or RUSTDESK_RES pointing at a directory holding them.

    python3 tests/pro_scripts_test.py
"""

import json
import os
import subprocess
import sys
import tempfile
import threading
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from russdesk.app import App  # noqa: E402
from russdesk.config import Config  # noqa: E402

# Pinned so a change upstream shows up as a deliberate bump, not a flaky test.
RUSTDESK_COMMIT = "53996e3c404ea5083df0775057e4149e49102084"
SCRIPTS = ("users", "user-groups", "device-groups", "devices", "strategies", "ab", "audits")
PASSWORD = "script-test-password"


def fetch_scripts():
    folder = os.environ.get("RUSTDESK_RES")
    if folder:
        return folder
    folder = tempfile.mkdtemp(prefix="rustdesk-res-")
    for name in SCRIPTS:
        url = f"https://raw.githubusercontent.com/rustdesk/rustdesk/{RUSTDESK_COMMIT}/res/{name}.py"
        urllib.request.urlretrieve(url, os.path.join(folder, f"{name}.py"))
    return folder


class Runner:
    def __init__(self, folder, base, token):
        self.folder, self.base, self.token = folder, base, token
        self.failures = []

    def check(self, label, ok):
        print(("PASS " if ok else "FAIL ") + "state: " + label)
        if not ok:
            self.failures.append(label)

    def run(self, script, *args, expect=None, stdin="Y\n"):
        cmd = [sys.executable, os.path.join(self.folder, f"{script}.py"), *args,
               "--url", self.base, "--token", self.token]
        proc = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=60)
        out = proc.stdout + proc.stderr
        label = f"{script} {' '.join(args)}"
        # Several scripts print "Error: ..." and still exit 0.
        ok = proc.returncode == 0 and "Error" not in out and (expect is None or expect in out)
        print(("PASS " if ok else "FAIL ") + label)
        if not ok:
            print("   exit", proc.returncode, "\n   " + out.strip().replace("\n", "\n   ")[:1500])
            self.failures.append(label)
        return out


def post(base, path, body, cookie=None, headers=None):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if cookie:
        req.add_header("Cookie", cookie)
    with urllib.request.urlopen(req) as resp:
        return resp.read(), resp.headers


def main():
    folder = fetch_scripts()
    data = tempfile.mkdtemp()
    app = App(Config(data_dir=data, host="127.0.0.1", port=0, admin_password=PASSWORD))
    ready = threading.Event()
    threading.Thread(target=app.serve, kwargs={"ready": lambda s: ready.set()}, daemon=True).start()
    ready.wait(5)
    base = "http://127.0.0.1:%d" % app.server.server_address[1]
    db = app.db

    # An admin creates a token with every permission, as in Settings > Tokens.
    _, headers = post(base, "/api/admin/login", {"username": "admin", "password": PASSWORD})
    cookie = headers["Set-Cookie"].split(";")[0]
    console = {"X-Russdesk": "1", "Content-Type": "application/json"}
    body, _ = post(base, "/api/admin/tokens", {"name": "scripts", "perms": {
        "device": 2, "audit": 2, "user": 2, "group": 2, "strategy": 2, "ab": 2}}, cookie, console)
    token = json.loads(body)["token"]
    post(base, "/api/admin/strategies", {"name": "Locked", "options": {"enable-file-transfer": "N"}}, cookie, console)
    # Two devices check in, one session is logged.
    for device in ("123456789", "987654321"):
        post(base, "/api/sysinfo", {"id": device, "uuid": "u" + device, "hostname": "host-" + device,
                                    "os": "windows / Windows 11"})
    post(base, "/api/audit/conn", {"id": "123456789", "uuid": "u", "conn_id": 1, "action": "new", "ip": "10.0.0.9"})
    post(base, "/api/audit/conn", {"id": "123456789", "uuid": "u", "conn_id": 1, "peer": ["555666777", "bob"],
                                   "type": 0})

    r = Runner(folder, base, token)
    # Groups
    r.run("device-groups", "add", "--name", "Servers")
    r.run("user-groups", "add", "--name", "Default")
    r.run("user-groups", "add", "--name", "Engineering", "--access-to", '[{"type":1,"name":"Servers"}]',
          "--accessed-from", '[{"type":0,"name":"Default"}]')
    r.run("user-groups", "view", "--name", "Engineering", expect="Servers")
    r.run("user-groups", "update", "--name", "Engineering", "--note", "builds")
    # Users
    r.run("users", "new", "--name", "carol", "--password", "carol-password", "--group_name", "Default",
          "--email", "carol@example.com")
    r.run("users", "view", "--name", "carol", expect="carol@example.com")
    r.run("user-groups", "add-users", "--name", "Engineering", "--users", "carol")
    r.run("user-groups", "view-users", "--name", "Engineering", expect="carol")
    r.run("users", "enable-2fa-enforce", "--name", "carol", "--web-console-url", base)
    r.run("users", "disable-2fa-enforce", "--name", "carol")
    r.run("users", "force-logout", "--name", "carol")
    r.run("users", "disable", "--name", "carol")
    r.run("users", "enable", "--name", "carol")
    # Devices
    r.run("devices", "view", expect="123456789")
    r.run("devices", "assign", "--id", "123456789", "--assign_to", "user_name=carol")
    r.run("devices", "assign", "--id", "123456789", "--assign_to", "note=front desk")
    r.run("devices", "view", "--user_name", "carol", expect="front desk")
    r.run("device-groups", "add-devices", "--name", "Servers", "--ids", "987654321")
    r.run("device-groups", "view-devices", "--name", "Servers", expect="987654321")
    r.run("device-groups", "remove-devices", "--name", "Servers", "--ids", "987654321")
    r.run("devices", "disable", "--id", "987654321")
    r.run("devices", "delete", "--id", "987654321")
    # Strategies
    r.run("strategies", "list", expect="Locked")
    r.run("strategies", "assign", "--name", "Locked", "--peers", "123456789", "--users", "carol",
          "--device-groups", "Servers")
    r.run("strategies", "view", "--name", "Locked", expect="123456789")
    r.run("strategies", "disable", "--name", "Locked")
    r.run("strategies", "enable", "--name", "Locked")
    r.run("strategies", "unassign", "--users", "carol")
    # Address books
    r.run("ab", "add-ab", "--ab-name", "Branch", "--note", "north", "--password", "shared-pw")
    r.run("ab", "view-ab", "--ab-name", "Branch", expect="shared-pw")
    guid = db.one("SELECT guid FROM address_books WHERE name = 'Branch'")["guid"]
    r.run("ab", "add-tag", "--ab-guid", guid, "--tag-name", "printers")
    r.run("ab", "view-tag", "--ab-guid", guid, expect="printers")
    r.run("ab", "add-peer", "--ab-guid", guid, "--peer-id", "123456789", "--alias", "Front", "--tags", "printers")
    r.run("ab", "view-peer", "--ab-guid", guid, expect="Front")
    r.run("ab", "update-peer", "--ab-guid", guid, "--peer-id", "123456789", "--note", "by the door")
    r.run("ab", "add-rule", "--ab-guid", guid, "--rule-type", "everyone", "--rule-permission", "ro")
    r.run("ab", "add-rule", "--ab-guid", guid, "--rule-type", "user", "--rule-user", "carol",
          "--rule-permission", "rw")
    r.run("ab", "view-rule", "--ab-guid", guid, expect="carol")
    rule_guid = db.one("SELECT rule_guid FROM ab_rules WHERE user_id IS NOT NULL")["rule_guid"]
    r.run("ab", "update-rule", "--ab-guid", guid, "--rule-guid", rule_guid, "--rule-permission", "full")
    rule = db.one("SELECT rule FROM ab_rules WHERE rule_guid = ?", (rule_guid,))
    r.check("rule updated to full control", rule is not None and rule["rule"] == 3)
    r.run("ab", "delete-rule", "--ab-guid", guid, "--rule-guid", rule_guid)
    r.check("rule deleted", db.one("SELECT 1 FROM ab_rules WHERE rule_guid = ?", (rule_guid,)) is None)
    r.run("ab", "delete-peer", "--ab-guid", guid, "--peer-id", "123456789")
    r.run("ab", "update-ab", "--ab-guid", guid, "--ab-update-name", "Branch North")
    r.run("ab", "get-personal-ab", expect="guid")
    # Audits
    r.run("audits", "view-conn", "--remote", "555666777", expect="Remote Desktop")
    r.run("audits", "view-console", "--page-size", "100", expect="Add User")
    r.run("audits", "view-alarm")
    r.run("audits", "view-file")
    # Clean-up paths
    r.run("users", "disable", "--name", "carol")
    r.run("users", "delete", "--name", "carol")
    r.run("user-groups", "delete", "--name", "Engineering")
    r.run("device-groups", "delete", "--name", "Servers")

    # The scripts reported success; check the server state they left behind.
    checks = {
        "carol deleted": db.one("SELECT 1 FROM users WHERE name = 'carol'") is None,
        "device deleted": db.one("SELECT 1 FROM devices WHERE id = '987654321'") is None,
        "note set": db.one("SELECT note FROM devices WHERE id = '123456789'")["note"] == "front desk",
        "device strategy": db.one("SELECT s.name FROM devices d JOIN strategies s ON s.id = d.strategy_id "
                                  "WHERE d.id = '123456789'")["name"] == "Locked",
        "book renamed": db.one("SELECT 1 FROM address_books WHERE name = 'Branch North'") is not None,
        "everyone rule": db.one("SELECT rule FROM ab_rules WHERE everyone = 1")["rule"] == 1,
        "peer in recycle bin": db.one("SELECT deleted_at FROM ab_peers WHERE peer_id = '123456789'")["deleted_at"],
    }
    for label, ok in checks.items():
        r.check(label, ok)
    app.shutdown()
    if r.failures:
        print(f"\n{len(r.failures)} failures")
        sys.exit(1)
    print("\nAll Pro scripts worked against RussDesk.")


if __name__ == "__main__":
    main()
