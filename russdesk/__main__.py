import argparse
import logging
import signal
import sys

from . import __version__
from .app import App
from .config import Config
from .security import hash_password


def main(argv=None):
    parser = argparse.ArgumentParser(prog="russdesk", description="RussDesk API server and web console")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--host", help="listen address (RUSSDESK_HOST, default 0.0.0.0)")
    parser.add_argument("--port", type=int, help="listen port (RUSSDESK_PORT, default 31114)")
    parser.add_argument("--data-dir", help="database and recordings (RUSSDESK_DATA_DIR, default ./data)")
    parser.add_argument("--reset-password", metavar="USER",
                        help="set a new password for USER (read from stdin) and exit")
    parser.add_argument("--debug", action="store_true", help="log every request")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    cfg = Config.from_env()
    if args.host:
        cfg.host = args.host
    if args.port is not None:
        cfg.port = args.port
    if args.data_dir:
        cfg.data_dir = args.data_dir

    app = App(cfg)
    if args.reset_password:
        password = sys.stdin.readline().rstrip("\n")
        if len(password) < 8:
            sys.exit("Password must be at least 8 characters")
        cur = app.db.run("UPDATE users SET password_hash = ?, totp_secret = '', status = 1 WHERE name = ?",
                         (hash_password(password), args.reset_password))
        if cur.rowcount == 0:
            sys.exit(f"No user named {args.reset_password}")
        app.db.run("DELETE FROM tokens WHERE user_id = (SELECT id FROM users WHERE name = ?)",
                   (args.reset_password,))
        print(f"Password reset for {args.reset_password}; two-factor login was turned off.")
        return

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        app.serve()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
