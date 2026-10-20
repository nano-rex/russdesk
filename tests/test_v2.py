"""Pro-parity features added in v0.2."""

import json
import os
import shutil
import tempfile
import unittest

from russdesk import auth
from russdesk.db import Database
from russdesk.models import BLOCK_WHITELIST
from russdesk.security import totp_now

from helpers import ADMIN_PASSWORD, ServerTest

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class MigrationTest(unittest.TestCase):
    def test_v1_database_upgrades(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "russdesk.db")
            shutil.copy(os.path.join(FIXTURES, "v1.db"), path)
            db = Database(path)
            self.assertEqual(db.meta("schema_version"), "2")
            for table in ("users", "user_groups", "device_groups", "strategies", "devices"):
                self.assertEqual(db.one(f"SELECT COUNT(*) AS n FROM {table} WHERE guid IS NULL")["n"], 0, table)
            rule = db.one("SELECT * FROM ab_rules")
            self.assertEqual((rule["user_id"], rule["rule"], rule["everyone"]), (2, 2, 0))
            self.assertTrue(rule["rule_guid"])
            access = db.one("SELECT * FROM access_rules")
            self.assertEqual(tuple(access), ("user_group", 1, "device_group", 1))
            self.assertIsNone(db.one("SELECT name FROM sqlite_master WHERE name = 'group_access'"))
            self.assertEqual(db.one("SELECT enabled FROM strategies")["enabled"], 1)
            self.assertIsNone(db.one("SELECT deleted_at FROM ab_peers")["deleted_at"])
            db.close()
            Database(path).close()  # migrating again is a no-op
        finally:
            shutil.rmtree(tmp)


class ClientCompatTest(ServerTest):
    def test_connection_note_from_controlling_side(self):
        base = {"id": "500", "uuid": "u", "conn_id": 1, "session_id": 777}
        self.client("POST", "/api/audit/conn", dict(base, action="new", ip="1.2.3.4"))
        # ui_session_interface.rs send_note: no conn_id, no nonce
        reply = self.client("POST", "/api/audit/conn", {"id": "500", "session_id": 777, "note": "fixed printer"})
        self.assertEqual((reply.status, reply.text), (200, ""))
        self.assertEqual(self.app.db.one("SELECT note FROM conn_logs")["note"], "fixed printer")

    def test_controller_recorded(self):
        self.client_login(device="600")  # admin logs in on the controlling device
        self.client("POST", "/api/audit/conn", {"id": "500", "uuid": "u", "conn_id": 1, "action": "new"})
        self.client("POST", "/api/audit/conn", {"id": "500", "uuid": "u", "conn_id": 1, "peer": ["600", "me"],
                                                "type": 0})
        self.assertEqual(self.app.db.one("SELECT controller FROM conn_logs")["controller"], "admin")

    def test_assign_from_command_line(self):
        self.console_login()
        uid = self.console("POST", "/api/admin/users", {"name": "kim", "password": "kim-password"}).json()["id"]
        token = self.console("POST", "/api/admin/tokens", {"name": "deploy", "perms": {"device": 2}}).json()["token"]
        self.console("POST", "/api/admin/device-groups", {"name": "Lab"})
        guid = self.console("POST", "/api/admin/address-books", {"name": "Fleet"}).json()["guid"]
        # core_main.rs --assign: POST /api/devices/cli with the API token
        reply = self.client("POST", "/api/devices/cli", {
            "id": "700", "uuid": "u7", "user_name": "kim", "device_group_name": "Lab", "note": "rack 2",
            "address_book_name": "Fleet", "address_book_tag": "lab", "device_name": "LAB-PC"}, token)
        self.assertEqual(reply.text, "")  # the client prints "Done!"
        row = self.app.db.one("SELECT * FROM devices WHERE id = '700'")
        self.assertEqual((row["user_id"], row["note"], row["name_override"]), (uid, "rack 2", "LAB-PC"))
        self.assertIsNotNone(self.app.db.one("SELECT 1 FROM ab_peers WHERE guid = ? AND peer_id = '700'", (guid,)))
        reply = self.client("POST", "/api/devices/cli", {"id": "700", "uuid": "u7", "user_name": "nobody"}, token)
        self.assertIn("not found", reply.text)
        self.assertEqual(self.client("POST", "/api/devices/cli", {"id": "700"}, "bad-token").text, "Invalid token")

    def test_disabled_device_is_blocked(self):
        self.console_login()
        hb = {"id": "800", "uuid": "u8", "modified_at": 0}
        self.client("POST", "/api/sysinfo", {"id": "800", "uuid": "u8", "hostname": "pc"})
        self.assertNotIn("strategy", self.client("POST", "/api/heartbeat", hb).json())
        self.console("POST", "/api/admin/devices/800/disable")
        blocked = self.client("POST", "/api/heartbeat", hb).json()
        self.assertEqual(blocked["strategy"]["config_options"], {"whitelist": BLOCK_WHITELIST})
        self.assertEqual(self.console("DELETE", "/api/admin/devices/800").status, 200)  # disabled first, as in Pro
        self.client("POST", "/api/heartbeat", hb)
        self.assertEqual(self.console("DELETE", "/api/admin/devices/800").status, 400)  # re-registered, enabled
        self.console("POST", "/api/admin/devices/800/disable")
        stamp = self.client("POST", "/api/heartbeat", hb).json()["modified_at"]
        self.console("POST", "/api/admin/devices/800/enable")
        reenabled = self.client("POST", "/api/heartbeat", dict(hb, modified_at=stamp)).json()
        self.assertEqual(reenabled["strategy"]["config_options"], {"whitelist": ""})

    def test_disabled_user_blocks_their_devices_and_hides_them(self):
        self.console_login()
        uid = self.console("POST", "/api/admin/users", {"name": "lee", "password": "lee-password"}).json()["id"]
        self.client_login("lee", "lee-password", device="900")
        admin = self.client_login(device="901")
        peers = lambda: [p["id"] for p in self.client("GET", "/api/peers?current=1&pageSize=50", token=admin).json()["data"]]
        self.assertIn("900", peers())
        self.console("POST", f"/api/admin/users/{uid}/disable")
        self.assertNotIn("900", peers())
        hb = self.client("POST", "/api/heartbeat", {"id": "900", "uuid": "uuid-900", "modified_at": 0}).json()
        self.assertEqual(hb["strategy"]["config_options"]["whitelist"], BLOCK_WHITELIST)

    def test_strategy_priority_and_disable(self):
        self.console_login()
        db = self.app.db
        s_user = self.console("POST", "/api/admin/strategies", {"name": "u", "options": {"enable-audio": "N"}}).json()["id"]
        s_group = self.console("POST", "/api/admin/strategies", {"name": "g", "options": {"enable-tunnel": "N"}}).json()["id"]
        dg = self.console("POST", "/api/admin/device-groups", {"name": "G", "strategy_id": s_group}).json()["id"]
        admin_id = db.one("SELECT id FROM users WHERE name = 'admin'")["id"]
        self.client_login(device="950")
        self.console("PATCH", "/api/admin/devices/950", {"device_group_id": dg})
        stamp = [0]

        def opts():  # like the client: echo back the last modified_at
            reply = self.client("POST", "/api/heartbeat",
                                {"id": "950", "uuid": "uuid-950", "modified_at": stamp[0]}).json()
            stamp[0] = reply.get("modified_at", stamp[0])
            return reply
        self.assertEqual(opts()["strategy"]["config_options"], {"enable-tunnel": "N"})
        self.console("PATCH", f"/api/admin/users/{admin_id}", {"strategy_id": s_user})
        # User beats group; the group strategy's option is reset to the default.
        self.assertEqual(opts()["strategy"]["config_options"], {"enable-audio": "N", "enable-tunnel": ""})
        self.console("PATCH", f"/api/admin/strategies/{s_user}", {"enabled": False})
        # Pro: a disabled strategy leaves the device unmanaged (no fallback to
        # the group's); what it set goes back to the defaults.
        reply = opts()
        self.assertEqual(reply["modified_at"], 0)
        self.assertEqual(reply["strategy"]["config_options"], {"enable-audio": ""})


class AddressBookV2Test(ServerTest):
    def setUp(self):
        super().setUp()
        self.console_login()
        self.g = self.console("POST", "/api/admin/user-groups", {"name": "Ops"}).json()["id"]
        self.uid = self.console("POST", "/api/admin/users", {"name": "ann", "password": "ann-password",
                                                             "group_id": self.g}).json()["id"]
        self.guid = self.console("POST", "/api/admin/address-books", {"name": "Shared", "password": "book-pw"}).json()["guid"]
        self.ann = self.client_login("ann", "ann-password", device="1000")

    def profiles(self):
        return self.client("POST", "/api/ab/shared/profiles?current=1&pageSize=50", token=self.ann).json()["data"]

    def test_everyone_rule_and_precedence(self):
        self.assertEqual(self.profiles(), [])
        self.console("PATCH", f"/api/admin/address-books/{self.guid}", {"rules": [
            {"everyone": True, "rule": 3}, {"user_group_id": self.g, "rule": 2}, {"user_id": self.uid, "rule": 1}]})
        profile = self.profiles()[0]
        self.assertEqual(profile["rule"], 1)  # user rule beats group and everyone, as in Pro
        self.assertEqual(profile["info"], {"password": "book-pw"})  # default shared password

    def test_recycle_bin(self):
        self.console("PATCH", f"/api/admin/address-books/{self.guid}", {"rules": [{"user_id": self.uid, "rule": 2}]})
        self.client("POST", f"/api/ab/peer/add/{self.guid}", {"id": "42", "alias": "kept"}, self.ann)
        self.client("DELETE", f"/api/ab/peer/{self.guid}", ["42"], self.ann)
        peers = self.client("POST", f"/api/ab/peers?current=1&pageSize=50&ab={self.guid}", token=self.ann).json()
        self.assertEqual(peers["total"], 0)
        recycled = self.console("GET", f"/api/admin/address-books/{self.guid}/recycle").json()["items"]
        self.assertEqual([p["id"] for p in recycled], ["42"])
        self.console("POST", f"/api/admin/address-books/{self.guid}/recycle/restore", {"ids": ["42"]})
        peers = self.client("POST", f"/api/ab/peers?current=1&pageSize=50&ab={self.guid}", token=self.ann).json()
        self.assertEqual(peers["data"][0]["alias"], "kept")

    def test_console_hides_peer_passwords(self):
        self.console("POST", f"/api/admin/address-books/{self.guid}/peers", {"id": "43", "password": "secret"})
        book = self.console("GET", f"/api/admin/address-books/{self.guid}").json()
        self.assertEqual(book["peers"][0]["password_set"], True)
        self.assertNotIn("secret", json.dumps(book))

    def test_non_admin_share_limits(self):
        self.console("POST", "/api/admin/logout")
        self.console_login("ann", "ann-password")
        own = self.console("POST", "/api/admin/address-books", {"name": "Mine"}).json()["guid"]
        reply = self.console("PATCH", f"/api/admin/address-books/{own}", {"rules": [{"everyone": True, "rule": 1}]})
        self.assertEqual(reply.status, 403)
        self.assertEqual(self.console("PATCH", f"/api/admin/address-books/{own}",
                                      {"rules": [{"user_group_id": self.g, "rule": 1}]}).status, 200)


class LoginSecurityTest(ServerTest):
    def test_login_alarm_after_repeated_failures(self):
        for _ in range(5):
            self.client("POST", "/api/login", {"username": "admin", "password": "wrong", "type": "account", "id": "77"})
        alarm = self.app.db.one("SELECT * FROM alarm_logs")
        self.assertEqual(alarm["typ"], 4)  # multiple login attempts within one minute
        self.assertEqual(json.loads(alarm["info"])["name"], "admin")

    def test_backup_code_login(self):
        self.console_login()
        setup = self.console("POST", "/api/admin/account/2fa/setup").json()
        codes = self.console("POST", "/api/admin/account/2fa/enable",
                             {"secret": setup["secret"], "code": totp_now(setup["secret"])}).json()["backup_codes"]
        self.assertEqual(len(codes), 6)
        first = self.client("POST", "/api/login", {"username": "admin", "password": ADMIN_PASSWORD,
                                                   "type": "account"}).json()
        ok = self.client("POST", "/api/login", {"type": "email_code", "tfaCode": codes[0], "verificationCode": codes[0],
                                                "secret": first["secret"], "username": "admin"}).json()
        self.assertEqual(ok["type"], "access_token")
        # Each backup code works once.
        again = self.client("POST", "/api/login", {"username": "admin", "password": ADMIN_PASSWORD,
                                                   "type": "account"}).json()
        reused = self.client("POST", "/api/login", {"type": "email_code", "tfaCode": codes[0],
                                                    "secret": again["secret"], "username": "admin"}).json()
        self.assertIn("error", reused)

    def test_enforced_2fa(self):
        self.console_login()
        uid = self.console("POST", "/api/admin/users", {"name": "ned", "password": "ned-password"}).json()["id"]
        self.console("PATCH", f"/api/admin/users/{uid}", {"force_2fa": True})
        reply = self.client("POST", "/api/login", {"username": "ned", "password": "ned-password", "type": "account"})
        self.assertIn("required", reply.json()["error"])
        self.console("POST", "/api/admin/logout")
        self.console_login("ned", "ned-password")
        self.assertTrue(self.console("GET", "/api/admin/me").json()["must_setup_2fa"])
        self.assertEqual(self.console("GET", "/api/admin/devices").status, 403)
        setup = self.console("POST", "/api/admin/account/2fa/setup").json()
        self.console("POST", "/api/admin/account/2fa/enable", {"secret": setup["secret"], "code": totp_now(setup["secret"])})
        self.assertEqual(self.console("GET", "/api/admin/devices").status, 200)

    def test_email_code_login(self):
        sent = []
        original = auth.mail.send
        auth.mail.send = lambda settings, to, subject, text: sent.append((to, text))
        try:
            self.console_login()
            self.console("PATCH", "/api/admin/settings", {"smtp_host": "smtp.example.com", "smtp_from": "rd@example.com"})
            self.console("PATCH", "/api/admin/account", {"email": "admin@example.com", "email_verification": True})
            first = self.client("POST", "/api/login", {"username": "admin", "password": ADMIN_PASSWORD,
                                                       "type": "account"}).json()
            self.assertEqual(first["type"], "email_check")
            self.assertNotIn("tfa_type", first)  # the client then asks for the emailed code
            code = sent[-1][1].split("code is ")[1][:6]
            ok = self.client("POST", "/api/login", {"type": "email_code", "verificationCode": code,
                                                    "secret": first["secret"], "username": "admin"}).json()
            self.assertEqual(ok["type"], "access_token")
        finally:
            auth.mail.send = original


class AdminRoleTest(ServerTest):
    def test_group_scoped_role(self):
        self.console_login()
        g1 = self.console("POST", "/api/admin/user-groups", {"name": "East"}).json()["id"]
        g2 = self.console("POST", "/api/admin/user-groups", {"name": "West"}).json()["id"]
        helper = self.console("POST", "/api/admin/users", {"name": "helper", "password": "helper-pass"}).json()["id"]
        east = self.console("POST", "/api/admin/users", {"name": "east1", "password": "east1-pass", "group_id": g1}).json()["id"]
        self.console("POST", "/api/admin/users", {"name": "west1", "password": "west1-pass", "group_id": g2})
        self.client_login("east1", "east1-pass", device="1101")
        self.client_login("west1", "west1-pass", device="1102")
        role = self.console("POST", "/api/admin/admin-roles", {
            "name": "East desk", "type": "group", "user_groups": [g1],
            "perms": ["users.view", "users.edit_note", "devices.view", "devices.enable_disable"],
            "users": [helper]})
        self.assertEqual(role.status, 201, role.text)
        bad = self.console("POST", "/api/admin/admin-roles", {"name": "x", "type": "group",
                                                              "perms": ["strategies.edit"]})
        self.assertEqual(bad.status, 400)  # global-only permission
        self.console("POST", "/api/admin/logout")
        self.console_login("helper", "helper-pass")
        me = self.console("GET", "/api/admin/me").json()
        self.assertIn("devices.enable_disable", me["perms"])
        self.assertEqual([u["name"] for u in self.console("GET", "/api/admin/users").json()["items"]], ["east1"])
        self.assertEqual([d["id"] for d in self.console("GET", "/api/admin/devices").json()["items"]], ["1101"])
        self.assertEqual(self.console("POST", "/api/admin/devices/1102/disable").status, 404)
        self.assertEqual(self.console("POST", "/api/admin/devices/1101/disable").status, 200)
        self.assertEqual(self.console("PATCH", f"/api/admin/users/{east}", {"note": "ok"}).status, 200)
        self.assertEqual(self.console("PATCH", f"/api/admin/users/{east}", {"email": "x@y"}).status, 403)
        admin_id = self.app.db.one("SELECT id FROM users WHERE name = 'admin'")["id"]
        self.assertEqual(self.console("PATCH", f"/api/admin/users/{admin_id}", {"note": "x"}).status, 403)


class ConsoleExtrasTest(ServerTest):
    def setUp(self):
        super().setUp()
        self.console_login()

    def test_windows_exe_name(self):
        self.console("PATCH", "/api/admin/settings", {"id_server": "rd.example.com:31116", "server_key": "K"})
        cfg = self.console("GET", "/api/admin/client-config").json()
        self.assertEqual(cfg["windows_exe"], f"rustdesk-licensed-{cfg['config_string']}.exe")

    def test_strategy_targets_and_duplicate(self):
        sid = self.console("POST", "/api/admin/strategies", {"name": "S", "options": {"enable-audio": "N"}}).json()["id"]
        self.client("POST", "/api/heartbeat", {"id": "1200", "uuid": "a", "modified_at": 0})
        self.console("POST", f"/api/admin/strategies/{sid}/targets", {"kind": "devices", "add": ["1200"]})
        items = self.console("GET", f"/api/admin/strategies/{sid}/targets?kind=devices").json()["items"]
        self.assertEqual(items[0]["strategies"], ["S", "-", "-"])
        self.assertTrue(items[0]["selected"])
        dup = self.console("POST", f"/api/admin/strategies/{sid}/duplicate").json()["id"]
        listing = {s["id"]: s for s in self.console("GET", "/api/admin/strategies").json()["items"]}
        self.assertEqual(listing[dup]["name"], "S (copy)")
        self.assertEqual(listing[sid]["applied"], 1)

    def test_conn_log_note_and_disconnect(self):
        self.client("POST", "/api/heartbeat", {"id": "1300", "uuid": "a", "conns": [5], "modified_at": 0})
        self.client("POST", "/api/audit/conn", {"id": "1300", "uuid": "a", "conn_id": 5, "action": "new"})
        log_id = self.console("GET", "/api/admin/logs/connections").json()["items"][0]["id"]
        self.assertEqual(self.console("GET", "/api/admin/logs/connections").json()["items"][0]["type"], "Not Logged In")
        self.console("PATCH", f"/api/admin/logs/connections/{log_id}", {"note": "checked"})
        self.console("POST", f"/api/admin/logs/connections/{log_id}/disconnect")
        hb = self.client("POST", "/api/heartbeat", {"id": "1300", "uuid": "a", "conns": [5], "modified_at": 0}).json()
        self.assertEqual(hb["disconnect"], [5])
        console = self.console("GET", "/api/admin/logs/console").json()["items"]
        self.assertTrue(any(i["operation"] == "Disconnect Device" for i in console))

    def test_invite_flow(self):
        sent = []
        original = __import__("russdesk.rest_api", fromlist=["mail"]).mail.send
        import russdesk.rest_api as rest
        rest.mail.send = lambda settings, to, subject, text: sent.append(text)
        try:
            self.console("PATCH", "/api/admin/settings", {"smtp_host": "smtp.example.com", "smtp_from": "rd@example.com"})
            reply = self.console("POST", "/api/admin/users/invite", {"name": "newbie", "email": "n@example.com"})
            self.assertEqual(reply.status, 201, reply.text)
            token = sent[0].split("/#/invite/")[1].split()[0]
            self.assertEqual(self.request("GET", f"/api/admin/invite/{token}").json()["name"], "newbie")
            self.assertEqual(self.client("POST", "/api/login", {"username": "newbie", "password": "whatever1",
                                                                "type": "account"}).json()["error"][:8], "Wrong us")
            self.request("POST", f"/api/admin/invite/{token}", {"password": "newbie-pass"})
            self.assertEqual(self.client("POST", "/api/login", {"username": "newbie", "password": "newbie-pass",
                                                                "type": "account"}).json()["type"], "access_token")
        finally:
            rest.mail.send = original


if __name__ == "__main__":
    unittest.main()
