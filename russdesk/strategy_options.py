"""Client settings a strategy can push. Keys come from the RustDesk client's
KEYS_SETTINGS (libs/base/src/config/keys.rs); the client applies whatever a
strategy sends, so the console also accepts custom keys."""

YES_NO = [["Y", "Yes"], ["N", "No"]]

STRATEGY_OPTIONS = [
    # Permissions granted to people who connect to this device
    {"key": "access-mode", "section": "Permissions", "label": "Permission preset",
     "type": "choice", "choices": [["custom", "Custom"], ["full", "Full access"], ["view", "Screen share only"]],
     "default": "custom"},
    {"key": "enable-keyboard", "section": "Permissions", "label": "Keyboard and mouse", "type": "bool", "default": "Y"},
    {"key": "enable-clipboard", "section": "Permissions", "label": "Clipboard", "type": "bool", "default": "Y"},
    {"key": "enable-file-transfer", "section": "Permissions", "label": "File transfer", "type": "bool", "default": "Y"},
    {"key": "enable-audio", "section": "Permissions", "label": "Audio", "type": "bool", "default": "Y"},
    {"key": "enable-camera", "section": "Permissions", "label": "Camera", "type": "bool", "default": "Y"},
    {"key": "enable-terminal", "section": "Permissions", "label": "Terminal", "type": "bool", "default": "Y"},
    {"key": "enable-remote-printer", "section": "Permissions", "label": "Remote printer", "type": "bool", "default": "Y"},
    {"key": "enable-tunnel", "section": "Permissions", "label": "TCP tunneling", "type": "bool", "default": "Y"},
    {"key": "enable-remote-restart", "section": "Permissions", "label": "Remote restart", "type": "bool", "default": "Y"},
    {"key": "enable-record-session", "section": "Permissions", "label": "Session recording", "type": "bool", "default": "Y"},
    {"key": "enable-block-input", "section": "Permissions", "label": "Block user input", "type": "bool", "default": "Y"},
    {"key": "enable-privacy-mode", "section": "Permissions", "label": "Privacy mode", "type": "bool", "default": "Y"},
    {"key": "allow-remote-config-modification", "section": "Permissions",
     "label": "Allow remote configuration modification", "type": "bool", "default": "N"},

    # How incoming connections are accepted
    {"key": "approve-mode", "section": "Security", "label": "Accept sessions",
     "type": "choice", "choices": [["", "Via password or click"], ["password", "Via password"], ["click", "Via click"]],
     "default": ""},
    {"key": "verification-method", "section": "Security", "label": "Password type",
     "type": "choice", "choices": [["use-both-passwords", "Temporary and permanent"],
                                   ["use-temporary-password", "Temporary only"],
                                   ["use-permanent-password", "Permanent only"]],
     "default": "use-both-passwords"},
    {"key": "temporary-password-length", "section": "Security", "label": "Temporary password length",
     "type": "choice", "choices": [["6", "6"], ["8", "8"], ["10", "10"]], "default": "6"},
    {"key": "allow-numeric-one-time-password", "section": "Security", "label": "Numeric one-time password",
     "type": "bool", "default": "N"},
    {"key": "enable-trusted-devices", "section": "Security", "label": "Trusted devices (skip 2FA)",
     "type": "bool", "default": "Y"},
    {"key": "allow-only-conn-window-open", "section": "Security",
     "label": "Only accept connections while the RustDesk window is open", "type": "bool", "default": "N"},
    {"key": "allow-auto-disconnect", "section": "Security", "label": "Disconnect idle sessions",
     "type": "bool", "default": "N"},
    {"key": "auto-disconnect-timeout", "section": "Security", "label": "Idle timeout (minutes)",
     "type": "text", "default": "10"},
    {"key": "whitelist", "section": "Security", "label": "IP whitelist (comma separated, CIDR allowed)",
     "type": "text", "default": ""},
    {"key": "id-whitelist", "section": "Security", "label": "ID whitelist (comma separated)",
     "type": "text", "default": ""},
    {"key": "allow-scope-violation-alarm", "section": "Security",
     "label": "Raise an alarm on session scope violation", "type": "bool", "default": "N"},
    {"key": "allow-scope-violation-close", "section": "Security",
     "label": "Close the session on scope violation", "type": "bool", "default": "N"},

    # Recording
    {"key": "allow-auto-record-incoming", "section": "Recording", "label": "Automatically record incoming sessions",
     "type": "bool", "default": "N"},

    # Network
    {"key": "enable-lan-discovery", "section": "Network", "label": "LAN discovery", "type": "bool", "default": "Y"},
    {"key": "direct-server", "section": "Network", "label": "Direct IP access", "type": "bool", "default": "N"},
    {"key": "direct-access-port", "section": "Network", "label": "Direct IP access port", "type": "text", "default": ""},
    {"key": "allow-websocket", "section": "Network", "label": "Use WebSocket", "type": "bool", "default": "N"},
    {"key": "disable-udp", "section": "Network", "label": "Disable UDP", "type": "bool", "default": "N"},
    {"key": "custom-rendezvous-server", "section": "Network", "label": "ID server", "type": "text", "default": ""},
    {"key": "relay-server", "section": "Network", "label": "Relay server", "type": "text", "default": ""},
    {"key": "api-server", "section": "Network", "label": "API server", "type": "text", "default": ""},
    {"key": "key", "section": "Network", "label": "Server key", "type": "text", "default": ""},
    {"key": "proxy-url", "section": "Network", "label": "Proxy URL", "type": "text", "default": ""},

    # Display and performance
    {"key": "enable-abr", "section": "Performance", "label": "Adaptive bitrate", "type": "bool", "default": "Y"},
    {"key": "enable-hwcodec", "section": "Performance", "label": "Hardware codec", "type": "bool", "default": "Y"},
    {"key": "allow-remove-wallpaper", "section": "Performance",
     "label": "Remove wallpaper during incoming sessions", "type": "bool", "default": "N"},
    {"key": "allow-always-software-render", "section": "Performance", "label": "Always software rendering",
     "type": "bool", "default": "N"},
    {"key": "keep-awake-during-incoming-sessions", "section": "Performance",
     "label": "Keep awake during incoming sessions", "type": "bool", "default": "Y"},
    {"key": "allow-auto-update", "section": "Performance", "label": "Auto update", "type": "bool", "default": "N"},
]

KNOWN_KEYS = {o["key"] for o in STRATEGY_OPTIONS}
