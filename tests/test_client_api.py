"""Requests shaped exactly like the RustDesk client's (see docs/client-protocol.md)."""

import base64
import json
import os
import unittest

from russdesk.security import totp_now

from helpers import ADMIN_PASSWORD, ServerTest

SYSINFO = {
    "cpu": "Intel(R) Core(TM) i5, 3.1GHz, 8/4 cores", "memory": "15.5GB",
    "os": "windows / Windows 11 Pro - 10.0.22631", "hostname": "DESK-01", "username": "alice",
    "version": "1.4.2", "id": "123456789", "uuid": "dXVpZA==",
}


class LoginTest(ServerTest):
    def test_login_current_user_logout(self):
        token = self.client_login()
        reply = self.client("POST", "/api/currentUser", {"id": "123456789", "uuid": "dXVpZA=="}, token)
        self.assertEqual(reply.status, 200)
        user = reply.json()
        self.assertEqual(user["name"], "admin")
        self.assertTrue(user["is_admin"])
        self.assertEqual(user["status"], 1)
        # Login binds the device to the account.
        device = self.app.db.one("SELECT user_id FROM devices WHERE id = '123456789'")
        self.assertIsNotNone(device["user_id"])
        self.assertEqual(self.client("POST", "/api/logout", {"id": "1", "uuid": "x"}, token).status, 200)
        self.assertEqual(self.client("POST", "/api/currentUser", {}, token).status, 401)

    def test_wrong_password(self):
        reply = self.client("POST", "/api/login", {"username": "admin", "password": "nope", "type": "account"})
        self.assertIn("error", reply.json())

    def test_rate_limit(self):
        for _ in range(10):
            self.client("POST", "/api/login", {"username": "admin", "password": "x", "type": "account"})
        reply = self.client("POST", "/api/login", {"username": "admin", "password": ADMIN_PASSWORD,
                                                   "type": "account"})
        self.assertIn("Too many", reply.json()["error"])

    def test_login_options(self):
        self.assertEqual(self.client("GET", "/api/login-options").json(), [])

    def test_totp_login(self):
        secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
        self.app.db.run("UPDATE users SET totp_secret = ? WHERE name = 'admin'", (secret,))
        first = self.client("POST", "/api/login", {"username": "admin", "password": ADMIN_PASSWORD,
                                                   "type": "account", "id": "1", "uuid": "u"}).json()
        self.assertEqual(first["type"], "email_check")
        self.assertEqual(first["tfa_type"], "tfa_check")
        bad = self.client("POST", "/api/login", {"username": "admin", "type": "email_code",
                                                 "verificationCode": "000000", "tfaCode": "000000",
                                                 "secret": first["secret"]}).json()
        self.assertIn("error", bad)
        code = totp_now(secret)
        ok = self.client("POST", "/api/login", {"username": "admin", "type": "email_code",
                                                "verificationCode": code, "tfaCode": code,
                                                "secret": first["secret"], "id": "1", "uuid": "u"}).json()
        self.assertEqual(ok["type"], "access_token")


class SyncTest(ServerTest):
    def test_heartbeat_sysinfo_cycle(self):
        hb = {"id": "123456789", "uuid": "dXVpZA==", "ver": 1004002, "modified_at": 0}
        first = self.client("POST", "/api/heartbeat", hb).json()
        self.assertIn("sysinfo", first)  # unknown device must upload sysinfo
        reply = self.client("POST", "/api/sysinfo", SYSINFO)
        self.assertEqual(reply.text, "SYSINFO_UPDATED")
        ver = self.client("POST", "/api/sysinfo_ver", raw=b"").text
        self.assertEqual(ver, self.app.db.meta("instance_id"))
        second = self.client("POST", "/api/heartbeat", hb).json()
        self.assertNotIn("sysinfo", second)
        row = self.app.db.one("SELECT * FROM devices WHERE id = '123456789'")
        self.assertEqual(row["hostname"], "DESK-01")
        self.assertEqual(row["os"], SYSINFO["os"])

    def test_strategy_push_and_clear(self):
        db = self.app.db
        cur = db.run("INSERT INTO strategies(name, options, modified_at) VALUES ('locked', ?, 100)",
                     (json.dumps({"enable-file-transfer": "N", "approve-mode": "click"}),))
        self.client("POST", "/api/sysinfo", SYSINFO)
        db.run("UPDATE devices SET strategy_id = ? WHERE id = '123456789'", (cur.lastrowid,))
        hb = {"id": "123456789", "uuid": "dXVpZA==", "ver": 1, "modified_at": 0}
        reply = self.client("POST", "/api/heartbeat", hb).json()
        self.assertEqual(reply["strategy"]["config_options"],
                         {"enable-file-transfer": "N", "approve-mode": "click"})
        stamp = reply["modified_at"]
        self.assertNotEqual(stamp, 0)
        # Same stamp back: nothing re-sent.
        again = self.client("POST", "/api/heartbeat", dict(hb, modified_at=stamp)).json()
        self.assertNotIn("strategy", again)
        # Unassigning resets what the strategy set.
        db.run("UPDATE devices SET strategy_id = NULL WHERE id = '123456789'")
        cleared = self.client("POST", "/api/heartbeat", dict(hb, modified_at=stamp)).json()
        self.assertEqual(cleared["modified_at"], 0)
        self.assertEqual(cleared["strategy"]["config_options"],
                         {"enable-file-transfer": "", "approve-mode": ""})

    def test_disconnect_queue(self):
        self.client("POST", "/api/sysinfo", SYSINFO)
        self.app.db.run("INSERT INTO pending_disconnects VALUES ('123456789', 7, 0)")
        hb = {"id": "123456789", "uuid": "dXVpZA==", "ver": 1, "conns": [7], "modified_at": 0}
        self.assertEqual(self.client("POST", "/api/heartbeat", hb).json()["disconnect"], [7])
        self.assertNotIn("disconnect", self.client("POST", "/api/heartbeat", hb).json())

    def test_device_id_change_follows_uuid(self):
        self.client("POST", "/api/sysinfo", SYSINFO)
        self.app.db.run("UPDATE devices SET note = 'keep me' WHERE id = '123456789'")
        self.client("POST", "/api/heartbeat", {"id": "987654321", "uuid": "dXVpZA==", "modified_at": 0})
        row = self.app.db.one("SELECT * FROM devices WHERE id = '987654321'")
        self.assertEqual(row["note"], "keep me")
        self.assertIsNone(self.app.db.one("SELECT 1 FROM devices WHERE id = '123456789'"))

    def test_presets(self):
        db = self.app.db
        db.run("INSERT INTO device_groups(name, created_at) VALUES ('Office', 0)")
        admin_id = db.one("SELECT id FROM users WHERE name = 'admin'")["id"]
        db.run("INSERT INTO address_books(guid, name, owner_id, personal, created_at) "
               "VALUES ('g1', 'Fleet', ?, 0, 0)", (admin_id,))
        info = dict(SYSINFO, **{"preset-device-group-name": "Office", "preset-user-name": "admin",
                                "preset-address-book-name": "Fleet", "preset-address-book-tag": "new",
                                "preset-address-book-alias": "Front desk"})
        self.client("POST", "/api/sysinfo", info)
        row = db.one("SELECT * FROM devices WHERE id = '123456789'")
        self.assertEqual(row["user_id"], admin_id)
        self.assertIsNotNone(row["device_group_id"])
        peer = db.one("SELECT * FROM ab_peers WHERE guid = 'g1'")
        self.assertEqual(peer["alias"], "Front desk")
        self.assertEqual(json.loads(peer["tags"]), ["new"])


class AuditTest(ServerTest):
    def test_connection_lifecycle(self):
        base = {"id": "123456789", "uuid": "dXVpZA==", "conn_id": 3, "session_id": 99}
        self.assertEqual(self.client("POST", "/api/audit/conn",
                                     dict(base, ip="10.0.0.5", action="new", nonce="n1")).text, "")
        # A retried post with the same nonce is stored once.
        self.client("POST", "/api/audit/conn", dict(base, ip="10.0.0.5", action="new", nonce="n1"))
        self.client("POST", "/api/audit/conn", dict(base, peer=["555666777", "bob"], type=1,
                                                    primary_auth=3, two_factor=1, nonce="n2"))
        rows = self.app.db.all("SELECT * FROM conn_logs")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["peer_id"], "555666777")
        self.assertEqual(rows[0]["type"], 1)
        self.client("POST", "/api/audit/conn", dict(base, action="close", nonce="n3"))
        self.assertIsNotNone(self.app.db.one("SELECT ended_at FROM conn_logs")["ended_at"])

    def test_file_and_alarm(self):
        self.client("POST", "/api/audit/file", {
            "id": "123456789", "uuid": "u", "peer_id": "555", "conn_id": 1, "type": 0,
            "path": "C:\\Users\\a", "is_file": False, "nonce": "f1",
            "info": json.dumps({"ip": "10.0.0.5", "name": "bob", "num": 2, "files": [["a.txt", 10]]}),
        })
        self.client("POST", "/api/audit/alarm", {
            "id": "123456789", "uuid": "u", "typ": 0, "conn_id": 1, "nonce": "a1",
            "info": json.dumps({"ip": "1.2.3.4"}),
        })
        self.assertEqual(self.app.db.one("SELECT COUNT(*) AS n FROM file_logs")["n"], 1)
        alarm = self.app.db.one("SELECT * FROM alarm_logs")
        self.assertEqual(alarm["ip"], "1.2.3.4")

    def test_rejects_bad_id(self):
        self.assertEqual(self.client("POST", "/api/audit/conn", {"conn_id": 1}).status, 400)


class AddressBookTest(ServerTest):
    def test_personal_book_flow(self):
        token = self.client_login()
        h = lambda m, p, b=None: self.client(m, p, b, token)
        self.assertEqual(h("POST", "/api/ab/settings").json(), {"max_peer_one_ab": 0})
        guid = h("POST", "/api/ab/personal").json()["guid"]
        self.assertEqual(h("POST", f"/api/ab/tag/add/{guid}", {"name": "work", "color": 123}).text, "")
        self.assertEqual(h("POST", f"/api/ab/peer/add/{guid}", {
            "id": "111", "alias": "srv", "tags": ["work", "ghost"], "hash": "h", "password": "p"}).text, "")
        peers = h("POST", f"/api/ab/peers?current=1&pageSize=100&ab={guid}").json()
        self.assertEqual(peers["total"], 1)
        peer = peers["data"][0]
        self.assertEqual(peer["tags"], ["work"])  # unknown tags dropped
        self.assertEqual(peer["hash"], "h")
        self.assertNotIn("password", peer)  # personal books keep hashes, not passwords
        h("PUT", f"/api/ab/peer/update/{guid}", {"id": "111", "note": "rack 4"})
        h("PUT", f"/api/ab/tag/rename/{guid}", {"old": "work", "new": "prod"})
        tags = h("POST", f"/api/ab/tags/{guid}").json()
        self.assertEqual(tags, [{"name": "prod", "color": 123}])
        peer = h("POST", f"/api/ab/peers?current=1&pageSize=100&ab={guid}").json()["data"][0]
        self.assertEqual((peer["note"], peer["tags"]), ("rack 4", ["prod"]))
        h("DELETE", f"/api/ab/tag/{guid}", ["prod"])
        h("DELETE", f"/api/ab/peer/{guid}", ["111"])
        self.assertEqual(h("POST", f"/api/ab/peers?current=1&pageSize=100&ab={guid}").json()["total"], 0)

    def test_shared_book_rules(self):
        self.console_login()
        uid = self.console("POST", "/api/admin/users", {"name": "bob", "password": "bob-password"}).json()["id"]
        guid = self.console("POST", "/api/admin/address-books", {"name": "Team"}).json()["guid"]
        bob = self.client_login("bob", "bob-password", device="222")
        self.assertEqual(self.client("POST", "/api/ab/shared/profiles?current=1&pageSize=100",
                                     token=bob).json()["total"], 0)
        self.assertEqual(self.client("POST", f"/api/ab/peers?current=1&pageSize=1&ab={guid}",
                                     token=bob).status, 403)
        self.console("PATCH", f"/api/admin/address-books/{guid}", {"rules": [{"user_id": uid, "rule": 1}]})
        profiles = self.client("POST", "/api/ab/shared/profiles?current=1&pageSize=100", token=bob).json()
        self.assertEqual(profiles["data"][0]["rule"], 1)
        self.assertEqual(profiles["data"][0]["owner"], "admin")
        self.assertEqual(self.client("POST", f"/api/ab/peer/add/{guid}", {"id": "1"}, bob).status, 403)
        self.console("PATCH", f"/api/admin/address-books/{guid}", {"rules": [{"user_id": uid, "rule": 2}]})
        self.assertEqual(self.client("POST", f"/api/ab/peer/add/{guid}",
                                     {"id": "1", "password": "secret", "hash": "x"}, bob).text, "")
        peer = self.client("POST", f"/api/ab/peers?current=1&pageSize=10&ab={guid}", token=bob).json()["data"][0]
        self.assertEqual(peer["password"], "secret")
        self.assertNotIn("hash", peer)

    def test_legacy_ab(self):
        token = self.client_login()
        data = {"tags": ["a"], "peers": [{"id": "9", "alias": "x", "tags": ["a"], "hash": "hh"}],
                "tag_colors": json.dumps({"a": 5})}
        self.assertEqual(self.client("POST", "/api/ab", {"data": json.dumps(data)}, token).status, 200)
        got = json.loads(self.client("GET", "/api/ab", token=token).json()["data"])
        self.assertEqual(got["tags"], ["a"])
        self.assertEqual(got["peers"][0]["hash"], "hh")
        self.assertEqual(json.loads(got["tag_colors"]), {"a": 5})


class AccessTest(ServerTest):
    def test_group_visibility(self):
        self.console_login()
        g1 = self.console("POST", "/api/admin/user-groups", {"name": "Support"}).json()["id"]
        g2 = self.console("POST", "/api/admin/user-groups", {"name": "Sales"}).json()["id"]
        dg = self.console("POST", "/api/admin/device-groups", {"name": "Kiosks"}).json()["id"]
        self.console("POST", "/api/admin/users", {"name": "sam", "password": "sam-password", "group_id": g1})
        self.console("POST", "/api/admin/users", {"name": "sue", "password": "sue-password", "group_id": g2})
        sue = self.client_login("sue", "sue-password", device="300")
        sam = self.client_login("sam", "sam-password", device="200")
        self.client("POST", "/api/sysinfo", dict(SYSINFO, id="400", uuid="k"))
        self.console("PATCH", "/api/admin/devices/400", {"device_group_id": dg})
        ids = lambda tok: sorted(p["id"] for p in self.client("GET", "/api/peers?current=1&pageSize=100&accessible=&status=1", token=tok).json()["data"])
        self.assertEqual(ids(sam), ["200"])
        self.console("PATCH", f"/api/admin/user-groups/{g1}",
                     {"access_user_groups": [g2], "access_device_groups": [dg]})
        self.assertEqual(ids(sam), ["200", "300", "400"])
        self.assertEqual(ids(sue), ["300"])
        users = self.client("GET", "/api/users?current=1&pageSize=100&accessible=&status=1", token=sam).json()
        self.assertEqual(sorted(u["name"] for u in users["data"]), ["sam", "sue"])
        groups = self.client("GET", "/api/device-group/accessible?current=1&pageSize=100", token=sam).json()
        self.assertEqual(groups["data"], [{"name": "Kiosks"}])


class RecordingTest(ServerTest):
    def test_upload(self):
        name = "incoming_123456789_20261018120000000_display0_vp9.webm"
        self.assertEqual(self.client("POST", f"/api/record?type=new&file={name}", raw=b"").status, 403)
        self.app.db.set_settings({"accept_recordings": True})
        self.assertEqual(self.client("POST", "/api/record?type=new&file=../x.webm", raw=b"").status, 400)
        self.client("POST", f"/api/record?type=new&file={name}", raw=b"")
        self.client("POST", f"/api/record?type=part&file={name}&offset=0&length=6", raw=b"HEADERbody")
        self.client("POST", f"/api/record?type=tail&file={name}&offset=0&length=6", raw=b"FIXED!")
        with open(os.path.join(self.app.cfg.recordings_dir, name), "rb") as f:
            self.assertEqual(f.read(), b"FIXED!body")
        self.assertIsNotNone(self.app.db.one("SELECT completed_at FROM recordings")["completed_at"])


class ConfigStringTest(ServerTest):
    def test_matches_client_decoder(self):
        self.console_login()
        self.console("PATCH", "/api/admin/settings", {"id_server": "rd.example.com", "server_key": "KEY=",
                                                      "api_server": "https://rd.example.com"})
        cfg = self.console("GET", "/api/admin/client-config").json()
        # ServerConfig.decode: reverse, base64.normalize, decode.
        raw = cfg["config_string"][::-1]
        decoded = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        self.assertEqual(decoded, {"host": "rd.example.com", "relay": "",
                                   "api": "https://rd.example.com", "key": "KEY="})

    def test_api_server_left_empty_by_default(self):
        self.console_login()
        self.console("PATCH", "/api/admin/settings", {"id_server": "rd.example.com", "server_key": "KEY="})
        cfg = self.console("GET", "/api/admin/client-config").json()
        raw = cfg["config_string"][::-1]
        decoded = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        self.assertEqual(decoded["api"], "")  # the client derives http://rd.example.com:21114
        self.assertEqual(cfg["api_default"], "http://rd.example.com:21114")


    def test_env_defaults_for_addresses(self):
        self.app.cfg.id_server = "203.0.113.5"
        self.app.cfg.relay_server = "relay.example.com"
        self.console_login()
        cfg = self.console("GET", "/api/admin/client-config").json()
        self.assertEqual((cfg["host"], cfg["relay"]), ("203.0.113.5", "relay.example.com"))
        self.console("PATCH", "/api/admin/settings", {"id_server": "rd.example.com"})
        self.assertEqual(self.console("GET", "/api/admin/client-config").json()["host"], "rd.example.com")


class TokenLifetimeTest(ServerTest):
    def test_client_login_never_expires_by_default(self):
        token = self.client_login()
        row = self.app.db.one("SELECT expires_at FROM tokens WHERE kind = 'client'")
        self.assertGreater(row["expires_at"], 250000000000)
        self.app.maintenance()
        self.assertEqual(self.client("POST", "/api/currentUser", {}, token).status, 200)

    def test_optional_lifetime(self):
        self.app.db.set_settings({"client_token_days": 1})
        self.client_login()
        row = self.app.db.one("SELECT expires_at, created_at FROM tokens WHERE kind = 'client'")
        self.assertEqual(row["expires_at"] - row["created_at"], 86400)


if __name__ == "__main__":
    unittest.main()
