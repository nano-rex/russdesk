//! Client settings a strategy can push. Port of strategy_options.py. Keys come
//! from the RustDesk client's KEYS_SETTINGS; the client applies whatever a
//! strategy sends, so the console also accepts custom keys.

use serde::Serialize;

#[derive(Clone, Serialize)]
pub struct StrategyOption {
    pub key: &'static str,
    pub section: &'static str,
    pub label: &'static str,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub default: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub choices: Option<Vec<[&'static str; 2]>>,
}

const fn opt(
    key: &'static str,
    section: &'static str,
    label: &'static str,
    kind: &'static str,
    default: &'static str,
) -> StrategyOption {
    StrategyOption {
        key,
        section,
        label,
        kind,
        default,
        choices: None,
    }
}

fn choice(
    key: &'static str,
    section: &'static str,
    label: &'static str,
    default: &'static str,
    choices: Vec<[&'static str; 2]>,
) -> StrategyOption {
    StrategyOption {
        key,
        section,
        label,
        kind: "choice",
        default,
        choices: Some(choices),
    }
}

/// The full option catalogue, in the order shown in the console.
pub fn strategy_options() -> Vec<StrategyOption> {
    vec![
        // Permissions
        choice("access-mode", "Permissions", "Permission preset", "custom",
            vec![["custom", "Custom"], ["full", "Full access"], ["view", "Screen share only"]]),
        opt("enable-keyboard", "Permissions", "Keyboard and mouse", "bool", "Y"),
        opt("enable-clipboard", "Permissions", "Clipboard", "bool", "Y"),
        opt("enable-file-transfer", "Permissions", "File transfer", "bool", "Y"),
        opt("enable-audio", "Permissions", "Audio", "bool", "Y"),
        opt("enable-camera", "Permissions", "Camera", "bool", "Y"),
        opt("enable-terminal", "Permissions", "Terminal", "bool", "Y"),
        opt("enable-remote-printer", "Permissions", "Remote printer", "bool", "Y"),
        opt("enable-tunnel", "Permissions", "TCP tunneling", "bool", "Y"),
        opt("enable-remote-restart", "Permissions", "Remote restart", "bool", "Y"),
        opt("enable-record-session", "Permissions", "Session recording", "bool", "Y"),
        opt("enable-block-input", "Permissions", "Block user input", "bool", "Y"),
        opt("enable-privacy-mode", "Permissions", "Privacy mode", "bool", "Y"),
        opt("allow-remote-config-modification", "Permissions",
            "Allow remote configuration modification", "bool", "N"),
        // Security
        choice("approve-mode", "Security", "Accept sessions", "",
            vec![["", "Via password or click"], ["password", "Via password"], ["click", "Via click"]]),
        choice("verification-method", "Security", "Password type", "use-both-passwords",
            vec![["use-both-passwords", "Temporary and permanent"],
                 ["use-temporary-password", "Temporary only"],
                 ["use-permanent-password", "Permanent only"]]),
        choice("temporary-password-length", "Security", "Temporary password length", "6",
            vec![["6", "6"], ["8", "8"], ["10", "10"]]),
        opt("allow-numeric-one-time-password", "Security", "Numeric one-time password", "bool", "N"),
        opt("enable-trusted-devices", "Security", "Trusted devices (skip 2FA)", "bool", "Y"),
        opt("allow-only-conn-window-open", "Security",
            "Only accept connections while the RustDesk window is open", "bool", "N"),
        opt("allow-auto-disconnect", "Security", "Disconnect idle sessions", "bool", "N"),
        opt("auto-disconnect-timeout", "Security", "Idle timeout (minutes)", "text", "10"),
        opt("whitelist", "Security", "IP whitelist (comma separated, CIDR allowed)", "text", ""),
        opt("id-whitelist", "Security", "ID whitelist (comma separated)", "text", ""),
        opt("allow-scope-violation-alarm", "Security",
            "Raise an alarm on session scope violation", "bool", "N"),
        opt("allow-scope-violation-close", "Security",
            "Close the session on scope violation", "bool", "N"),
        // Recording
        opt("allow-auto-record-incoming", "Recording",
            "Automatically record incoming sessions", "bool", "N"),
        // Network
        opt("enable-lan-discovery", "Network", "LAN discovery", "bool", "Y"),
        opt("direct-server", "Network", "Direct IP access", "bool", "N"),
        opt("direct-access-port", "Network", "Direct IP access port", "text", ""),
        opt("allow-websocket", "Network", "Use WebSocket", "bool", "N"),
        opt("disable-udp", "Network", "Disable UDP", "bool", "N"),
        opt("custom-rendezvous-server", "Network", "ID server", "text", ""),
        opt("relay-server", "Network", "Relay server", "text", ""),
        opt("api-server", "Network", "API server", "text", ""),
        opt("key", "Network", "Server key", "text", ""),
        opt("proxy-url", "Network", "Proxy URL", "text", ""),
        // Performance
        opt("enable-abr", "Performance", "Adaptive bitrate", "bool", "Y"),
        opt("enable-hwcodec", "Performance", "Hardware codec", "bool", "Y"),
        opt("allow-remove-wallpaper", "Performance",
            "Remove wallpaper during incoming sessions", "bool", "N"),
        opt("allow-always-software-render", "Performance", "Always software rendering", "bool", "N"),
        opt("keep-awake-during-incoming-sessions", "Performance",
            "Keep awake during incoming sessions", "bool", "Y"),
        opt("allow-auto-update", "Performance", "Auto update", "bool", "N"),
    ]
}

/// Keys the console recognises (custom keys are also accepted elsewhere).
pub fn known_keys() -> std::collections::HashSet<&'static str> {
    strategy_options().into_iter().map(|o| o.key).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_matches_python() {
        let opts = strategy_options();
        assert_eq!(opts.len(), 43);
        let keys = known_keys();
        assert!(keys.contains("custom-rendezvous-server"));
        assert!(keys.contains("relay-server"));
        assert!(keys.contains("key"));
        assert!(keys.contains("access-mode"));
    }

    #[test]
    fn choice_options_have_choices() {
        let opts = strategy_options();
        let am = opts.iter().find(|o| o.key == "access-mode").unwrap();
        assert_eq!(am.kind, "choice");
        assert!(am.choices.is_some());
        let kb = opts.iter().find(|o| o.key == "enable-keyboard").unwrap();
        assert!(kb.choices.is_none());
    }
}
