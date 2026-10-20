import unittest

from helpers import ADMIN_PASSWORD, ServerTest


class ConsoleAuthTest(ServerTest):
    def test_requires_login_and_csrf_header(self):
        self.assertEqual(self.console("GET", "/api/admin/me").status, 401)
        self.console_login()
        self.assertEqual(self.console("GET", "/api/admin/me").json()["name"], "admin")
        # A cross-site form post cannot add the custom header.
        reply = self.request("POST", "/api/admin/users", {"name": "x", "password": "12345678"},
                             headers={"Cookie": self.cookie})
        self.assertEqual(reply.status, 403)

    def test_cookie_flags(self):
        reply = self.console_login()
        cookie = reply.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)

    def test_wrong_password(self):
        reply = self.console("POST", "/api/admin/login", {"username": "admin", "password": "bad"})
        self.assertEqual(reply.status, 401)

    def test_non_admin_is_limited(self):
        self.console_login()
        self.console("POST", "/api/admin/users", {"name": "eve", "password": "eve-password"})
        self.console("POST", "/api/admin/logout")
        self.console_login("eve", "eve-password")
        self.assertEqual(self.console("GET", "/api/admin/users").status, 403)
        self.assertEqual(self.console("GET", "/api/admin/admin-roles").status, 403)
        # Like Pro, a normal user sees only their own logs.
        self.assertEqual(self.console("GET", "/api/admin/logs/connections").json()["total"], 0)
        self.assertEqual(self.console("GET", "/api/admin/devices").status, 200)
        self.assertEqual(self.console("GET", "/api/admin/address-books").status, 200)

    def test_last_admin_is_protected(self):
        self.console_login()
        admin_id = self.console("GET", "/api/admin/me").json()["id"]
        self.assertEqual(self.console("PATCH", f"/api/admin/users/{admin_id}", {"is_admin": False}).status, 400)
        self.assertEqual(self.console("DELETE", f"/api/admin/users/{admin_id}").status, 400)

    def test_disabling_user_revokes_tokens(self):
        self.console_login()
        uid = self.console("POST", "/api/admin/users", {"name": "tim", "password": "tim-password"}).json()["id"]
        token = self.client_login("tim", "tim-password", device="77")
        self.assertEqual(self.console("POST", f"/api/admin/users/{uid}/disable").status, 200)
        self.assertEqual(self.client("POST", "/api/currentUser", {}, token).status, 401)


class ConsoleDataTest(ServerTest):
    def setUp(self):
        super().setUp()
        self.console_login()

    def test_device_listing_and_disconnect(self):
        self.client("POST", "/api/sysinfo", {"id": "1001", "uuid": "a", "hostname": "pc", "os": "linux / Debian"})
        self.client("POST", "/api/heartbeat", {"id": "1001", "uuid": "a", "conns": [4], "modified_at": 0})
        items = self.console("GET", "/api/admin/devices?status=online").json()["items"]
        self.assertEqual([d["id"] for d in items], ["1001"])
        self.assertEqual(items[0]["platform"], "Linux")
        self.console("POST", "/api/admin/devices/1001/disconnect", {})
        hb = self.client("POST", "/api/heartbeat", {"id": "1001", "uuid": "a", "conns": [4], "modified_at": 0})
        self.assertEqual(hb.json()["disconnect"], [4])

    def test_strategy_edit_resends(self):
        sid = self.console("POST", "/api/admin/strategies",
                           {"name": "base", "options": {"enable-audio": "N"}}).json()["id"]
        self.console("PATCH", "/api/admin/settings", {"default_strategy_id": sid})
        hb = {"id": "1002", "uuid": "b", "modified_at": 0}
        first = self.client("POST", "/api/heartbeat", hb).json()
        self.assertEqual(first["strategy"]["config_options"], {"enable-audio": "N"})
        self.console("PATCH", f"/api/admin/strategies/{sid}", {"options": {"enable-audio": "N", "enable-tunnel": "N"}})
        second = self.client("POST", "/api/heartbeat", dict(hb, modified_at=first["modified_at"])).json()
        self.assertEqual(second["strategy"]["config_options"], {"enable-audio": "N", "enable-tunnel": "N"})
        self.assertNotEqual(second["modified_at"], first["modified_at"])

    def test_logs_and_csv(self):
        self.client("POST", "/api/audit/conn", {"id": "1003", "uuid": "c", "conn_id": 1, "action": "new",
                                                "ip": "10.1.1.1", "session_id": 1})
        self.client("POST", "/api/audit/conn", {"id": "1003", "uuid": "c", "conn_id": 1,
                                                "peer": ["=cmd", "mallory"], "type": 0})
        data = self.console("GET", "/api/admin/logs/connections").json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["type"], "Remote Desktop")
        csv_text = self.console("GET", "/api/admin/logs/connections?format=csv").text
        self.assertIn("'=cmd", csv_text)  # formula injection neutralised
        console_log = self.console("GET", "/api/admin/logs/console").json()
        self.assertTrue(any(i["action"] == "login" for i in console_log["items"]))

    def test_address_book_console(self):
        guid = self.console("POST", "/api/admin/address-books", {"name": "Ops"}).json()["guid"]
        self.console("POST", f"/api/admin/address-books/{guid}/tags", {"name": "db", "color": 1})
        self.assertEqual(self.console("POST", f"/api/admin/address-books/{guid}/peers",
                                      {"id": "55", "alias": "db1", "tags": ["db"], "password": "pw"}).status, 201)
        self.assertEqual(self.console("POST", f"/api/admin/address-books/{guid}/peers", {"id": "55"}).status, 409)
        book = self.console("GET", f"/api/admin/address-books/{guid}").json()
        self.assertEqual(book["peers"][0]["tags"], ["db"])
        self.console("PATCH", f"/api/admin/address-books/{guid}/tags/db", {"name": "database"})
        book = self.console("GET", f"/api/admin/address-books/{guid}").json()
        self.assertEqual(book["peers"][0]["tags"], ["database"])

    def test_totp_enable(self):
        from russdesk.security import totp_now
        setup = self.console("POST", "/api/admin/account/2fa/setup").json()
        self.assertTrue(setup["uri"].startswith("otpauth://totp/"))
        self.assertEqual(self.console("POST", "/api/admin/account/2fa/enable",
                                      {"secret": setup["secret"], "code": "000000"}).status, 400)
        self.assertEqual(self.console("POST", "/api/admin/account/2fa/enable",
                                      {"secret": setup["secret"], "code": totp_now(setup["secret"])}).status, 200)
        self.console("POST", "/api/admin/logout")
        self.assertTrue(self.console("POST", "/api/admin/login",
                                     {"username": "admin", "password": ADMIN_PASSWORD}).json()["need_code"])

    def test_static_shell_and_headers(self):
        reply = self.request("GET", "/devices")
        self.assertEqual(reply.status, 200)
        self.assertIn("Content-Security-Policy", reply.headers)
        self.assertEqual(self.request("GET", "/../../etc/passwd").status, 200)  # serves the shell, not the file
        self.assertNotIn(b"root:", self.request("GET", "/../../etc/passwd").body)


if __name__ == "__main__":
    unittest.main()
