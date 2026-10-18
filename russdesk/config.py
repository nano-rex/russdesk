"""Runtime configuration, read once from environment variables."""

import os
from dataclasses import dataclass, field


def _bool(value, default=False):
    if value is None or value == "":
        return default
    return value.strip().lower() in ("1", "y", "yes", "true", "on")


@dataclass
class Config:
    data_dir: str = "./data"
    host: str = "0.0.0.0"
    port: int = 21114
    # Path to hbbs' public key (id_ed25519.pub); shown in the console so
    # admins can hand it to clients.
    hbbs_key_file: str = ""
    # Trust X-Forwarded-For / X-Forwarded-Proto from a reverse proxy.
    trust_proxy: bool = False
    # Initial admin account, created only when the user table is empty.
    admin_user: str = "admin"
    admin_password: str = ""
    static_dir: str = field(
        default_factory=lambda: os.path.join(os.path.dirname(__file__), "static")
    )

    @property
    def db_path(self):
        return os.path.join(self.data_dir, "russdesk.db")

    @property
    def recordings_dir(self):
        return os.path.join(self.data_dir, "recordings")

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        cfg = cls()
        cfg.data_dir = env.get("RUSSDESK_DATA_DIR", cfg.data_dir)
        cfg.host = env.get("RUSSDESK_HOST", cfg.host)
        cfg.port = int(env.get("RUSSDESK_PORT", cfg.port))
        cfg.hbbs_key_file = env.get("RUSSDESK_HBBS_KEY_FILE", cfg.hbbs_key_file)
        cfg.trust_proxy = _bool(env.get("RUSSDESK_TRUST_PROXY"), cfg.trust_proxy)
        cfg.admin_user = env.get("RUSSDESK_ADMIN_USER", cfg.admin_user)
        cfg.admin_password = env.get("RUSSDESK_ADMIN_PASSWORD", cfg.admin_password)
        return cfg
