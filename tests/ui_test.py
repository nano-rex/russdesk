"""Drive the console in headless Chromium (needs: pip install playwright;
python -m playwright install chromium). Screenshots go to $UI_SHOTS or ./ui-shots."""

import json
import os
import sys
import tempfile
import threading
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from playwright.sync_api import expect, sync_playwright  # noqa: E402

from russdesk.app import App  # noqa: E402
from russdesk.config import Config  # noqa: E402

PASSWORD = "ui-test-password"
SHOTS = os.environ.get("UI_SHOTS", "ui-shots")


def post(base, path, body):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST")
    with urllib.request.urlopen(req) as resp:
        return resp.read()


def seed(base):
    """Pretend to be two RustDesk clients."""
    for device, host, os_name in (("123456789", "FRONT-DESK", "windows / Windows 11 Pro - 10.0.22631"),
                                  ("987654321", "build-box", "linux / Ubuntu 24.04")):
        post(base, "/api/sysinfo", {"id": device, "uuid": "u" + device, "hostname": host, "os": os_name,
                                    "username": "alice", "cpu": "8 cores", "memory": "16GB", "version": "1.4.2"})
        post(base, "/api/heartbeat", {"id": device, "uuid": "u" + device, "conns": [1], "modified_at": 0})
    post(base, "/api/audit/conn", {"id": "123456789", "uuid": "u", "conn_id": 1, "action": "new", "ip": "10.0.0.8"})
    post(base, "/api/audit/conn", {"id": "123456789", "uuid": "u", "conn_id": 1, "peer": ["555000111", "bob"],
                                   "type": 0, "primary_auth": 2})
    post(base, "/api/audit/alarm", {"id": "987654321", "uuid": "u", "typ": 2, "conn_id": 3,
                                    "info": json.dumps({"ip": "203.0.113.9"})})


def main():
    os.makedirs(SHOTS, exist_ok=True)
    data = tempfile.mkdtemp()
    app = App(Config(data_dir=data, host="127.0.0.1", port=0, admin_password=PASSWORD))
    ready = threading.Event()
    threading.Thread(target=app.serve, kwargs={"ready": lambda s: ready.set()}, daemon=True).start()
    ready.wait(5)
    base = "http://127.0.0.1:%d" % app.server.server_address[1]
    seed(base)
    errors = []

    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            run(browser, base, errors)
        except Exception:
            for pg in browser.contexts[-1].pages if browser.contexts else []:
                pg.screenshot(path=f"{SHOTS}/failure.png", full_page=True)
                print("URL:", pg.url)
                print(pg.inner_text("body")[:3000])
            print("\n".join(errors))
            raise
        browser.close()

    app.shutdown()
    errors = [e for e in errors if "401" not in e]  # expected before login
    if errors:
        print("\n".join(errors))
        sys.exit(1)
    print("UI test passed; screenshots in", SHOTS)


def run(browser, base, errors):
    for scheme in ("light", "dark"):
        page = browser.new_page(viewport={"width": 1280, "height": 860}, color_scheme=scheme)
        page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
        page.on("console", lambda m: errors.append(f"console: {m.text}") if m.type == "error" else None)
        page.goto(base + "/")
        page.get_by_label("Username").fill("admin")
        page.get_by_label("Password").fill(PASSWORD)
        page.get_by_role("button", name="Sign in").click()
        expect(page.get_by_role("heading", name="Dashboard")).to_be_visible()
        expect(page.get_by_text("555000111")).to_be_visible()  # active session
        page.screenshot(path=f"{SHOTS}/dashboard-{scheme}.png", full_page=True)
        if scheme == "dark":
            page.close()
            continue

        # Devices: list and detail dialog
        page.goto(base + "/#/devices")
        expect(page.get_by_text("FRONT-DESK")).to_be_visible()
        page.screenshot(path=f"{SHOTS}/devices.png", full_page=True)
        page.get_by_text("FRONT-DESK").click()
        expect(page.get_by_role("dialog")).to_be_visible()
        page.screenshot(path=f"{SHOTS}/device-dialog.png")
        page.get_by_role("dialog").get_by_label("Note").fill("Reception PC")
        page.get_by_role("button", name="Save").click()
        expect(page.get_by_text("Reception PC")).to_be_visible()

        # Users: create one through the form
        page.goto(base + "/#/users")
        page.get_by_role("button", name="New user").click()
        dialog = page.get_by_role("dialog")
        dialog.get_by_label("Username").fill("carol")
        dialog.get_by_label("Password").fill("carol-password")
        dialog.get_by_role("button", name="Create").click()
        expect(page.get_by_role("cell", name="carol", exact=True)).to_be_visible()
        page.screenshot(path=f"{SHOTS}/users.png", full_page=True)

        # Groups
        page.goto(base + "/#/groups/devices")
        page.get_by_role("button", name="New device group").click()
        page.get_by_role("dialog").get_by_label("Name").fill("Front office")
        page.get_by_role("dialog").get_by_role("button", name="Create").click()
        expect(page.get_by_role("cell", name="Front office")).to_be_visible()
        page.screenshot(path=f"{SHOTS}/groups.png", full_page=True)

        # Strategy editor: enforce one setting, make it the default
        page.goto(base + "/#/strategies")
        page.get_by_role("button", name="New strategy").click()
        dialog = page.get_by_role("dialog")
        dialog.get_by_label("Name", exact=True).fill("Locked down")
        dialog.get_by_label("Set File transfer").check()
        dialog.locator(".opt", has_text="File transfer").locator("select").select_option("N")
        dialog.get_by_label("Default strategy").check()
        page.screenshot(path=f"{SHOTS}/strategy-editor.png")
        dialog.get_by_role("button", name="Create").click()
        expect(page.get_by_text("Locked down")).to_be_visible()
        hb = json.loads(post(base, "/api/heartbeat", {"id": "987654321", "uuid": "u987654321", "modified_at": 0}))
        assert hb["strategy"]["config_options"] == {"enable-file-transfer": "N"}, hb

        # Address book with a tag and a peer
        page.goto(base + "/#/address-books")
        page.get_by_role("button", name="New shared address book").click()
        page.get_by_role("dialog").get_by_label("Name").fill("Branch office")
        page.get_by_role("dialog").get_by_role("button", name="Create").click()
        expect(page.get_by_role("heading", name="Branch office")).to_be_visible()
        page.get_by_role("tab", name="Tags").click()
        page.get_by_placeholder("New tag").fill("printers")
        page.get_by_role("button", name="Add tag").click()
        expect(page.locator(".tag", has_text="printers")).to_be_visible()
        page.get_by_role("tab", name="Devices").click()
        page.get_by_role("button", name="Add", exact=True).click()
        dialog = page.get_by_role("dialog")
        dialog.get_by_label("RustDesk ID").fill("123456789")
        dialog.get_by_label("Alias").fill("Front desk")
        dialog.get_by_text("printers").click()
        dialog.get_by_role("button", name="Add", exact=True).click()
        expect(page.get_by_role("cell", name="Front desk")).to_be_visible()
        page.screenshot(path=f"{SHOTS}/address-book.png", full_page=True)
        page.get_by_role("tab", name="Sharing").click()
        page.get_by_label("Share with").select_option(label="Everyone")
        page.get_by_role("button", name="Save sharing").click()
        expect(page.get_by_text("Sharing saved")).to_be_visible()

        # Admin roles and API tokens
        page.goto(base + "/#/admin-roles")
        page.get_by_role("button", name="New role").click()
        dialog = page.get_by_role("dialog")
        dialog.get_by_label("Name", exact=True).fill("Helpdesk")
        dialog.get_by_text("Devices - View").click()
        dialog.get_by_role("button", name="Create").click()
        expect(page.get_by_role("cell", name="Helpdesk")).to_be_visible()
        page.screenshot(path=f"{SHOTS}/admin-roles.png", full_page=True)
        page.goto(base + "/#/settings/tokens")
        page.get_by_role("button", name="Create token").click()
        dialog = page.get_by_role("dialog")
        dialog.get_by_label("Name", exact=True).fill("scripts")
        dialog.get_by_label("device").select_option("2")
        dialog.get_by_role("button", name="Create").click()
        expect(page.get_by_text("Copy it now")).to_be_visible()
        page.keyboard.press("Escape")
        expect(page.get_by_role("cell", name="scripts")).to_be_visible()
        page.screenshot(path=f"{SHOTS}/tokens.png", full_page=True)

        # Logs, settings, account
        for kind in ("connections", "alarms", "console"):
            page.goto(base + "/#/logs/" + kind)
            expect(page.locator("table")).to_be_visible()
            page.screenshot(path=f"{SHOTS}/logs-{kind}.png", full_page=True)
        page.goto(base + "/#/settings/general")
        expect(page.get_by_text("Scan on a phone")).to_be_visible()
        page.screenshot(path=f"{SHOTS}/settings.png", full_page=True)
        page.goto(base + "/#/account")
        page.get_by_role("button", name="Enable 2FA").click()
        expect(page.get_by_role("img", name="QR code")).to_be_visible()
        page.screenshot(path=f"{SHOTS}/account-2fa.png")
        page.keyboard.press("Escape")

        # Phone width: no horizontal scroll
        page.set_viewport_size({"width": 390, "height": 800})
        page.goto(base + "/#/devices")
        expect(page.get_by_role("heading", name="Devices")).to_be_visible()
        overflow = page.evaluate("document.documentElement.scrollWidth - window.innerWidth")
        assert overflow <= 1, f"page scrolls sideways by {overflow}px"
        page.screenshot(path=f"{SHOTS}/mobile-devices.png", full_page=True)

        page.get_by_role("button", name="Menu").click()
        page.get_by_role("button", name="Sign out").click()
        expect(page.get_by_role("button", name="Sign in")).to_be_visible()
        page.close()


if __name__ == "__main__":
    main()
