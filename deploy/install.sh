#!/bin/sh
# Install RussDesk plus RustDesk's open-source hbbs/hbbr on a bare-metal
# Linux server with systemd. Run from a checkout of the repository:
#
#   sudo ./deploy/install.sh --host rd.example.com
#
# Re-running upgrades the code and binaries and keeps all data and settings.
#   --host ADDR          public DNS name or IP clients connect to (default: first local IP)
#   --admin-password PW  first console password (default: random, printed at the end)
#   --rustdesk-version V hbbs/hbbr release (default: latest)
#   --skip-rustdesk      hbbs/hbbr already run elsewhere on this host; install RussDesk only
#   --no-firewall        do not touch ufw/firewalld
#   --uninstall          stop and remove services, binaries and code (data is kept)
set -eu

PREFIX_BIN=/usr/local/bin
APP_DIR=/opt/russdesk
HBBS_DIR=/var/lib/rustdesk-server
DATA_DIR=/var/lib/russdesk
ENV_FILE=/etc/russdesk.env
UNIT_DIR=/etc/systemd/system
SVC_USER=rustdesk

HOST=""
ADMIN_PASSWORD=""
RD_VERSION="latest"
SKIP_RUSTDESK=0
FIREWALL=1
UNINSTALL=0

die() { echo "error: $*" >&2; exit 1; }
say() { printf '\033[1m==>\033[0m %s\n' "$*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --host) HOST="${2:?}"; shift 2 ;;
        --admin-password) ADMIN_PASSWORD="${2:?}"; shift 2 ;;
        --rustdesk-version) RD_VERSION="${2:?}"; shift 2 ;;
        --skip-rustdesk) SKIP_RUSTDESK=1; shift ;;
        --no-firewall) FIREWALL=0; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "run as root (sudo $0 ...)"
command -v systemctl >/dev/null || die "systemd is required"

if [ "$UNINSTALL" -eq 1 ]; then
    say "Stopping and removing services"
    for s in russdesk rustdesk-hbbs rustdesk-hbbr; do
        systemctl disable --now "$s" 2>/dev/null || true
        rm -f "$UNIT_DIR/$s.service"
    done
    systemctl daemon-reload
    rm -rf "$APP_DIR"
    rm -f "$PREFIX_BIN/hbbs" "$PREFIX_BIN/hbbr" "$PREFIX_BIN/rustdesk-utils"
    echo "Removed. Kept: $DATA_DIR, $HBBS_DIR (server key), $ENV_FILE and the '$SVC_USER' user."
    echo "Delete them by hand for a clean slate: rm -rf $DATA_DIR $HBBS_DIR $ENV_FILE; userdel $SVC_USER"
    exit 0
fi

SRC_DIR=$(cd "$(dirname "$0")/.." && pwd)
[ -f "$SRC_DIR/russdesk/__main__.py" ] || die "run this script from a RussDesk checkout"

# -- prerequisites ---------------------------------------------------------------
command -v python3 >/dev/null || die "python3 is required (apt install python3 / dnf install python3)"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' \
    || die "Python 3.10 or newer is required (found $(python3 -V 2>&1))"
python3 -c 'import sqlite3' 2>/dev/null || die "Python's sqlite3 module is missing"

fetch() {  # fetch URL FILE
    if command -v curl >/dev/null; then curl -fsSL --retry 3 -o "$2" "$1"
    elif command -v wget >/dev/null; then wget -q -O "$2" "$1"
    else die "curl or wget is required"; fi
}

if [ -z "$HOST" ]; then
    HOST=$(hostname -I 2>/dev/null | awk '{print $1}')
    [ -n "$HOST" ] || die "could not detect an IP address; pass --host"
    echo "No --host given; using $HOST. Pass --host with your public name or IP if clients connect from outside."
fi

# -- service user and directories -------------------------------------------------
if ! id "$SVC_USER" >/dev/null 2>&1; then
    say "Creating system user $SVC_USER"
    useradd --system --home-dir "$HBBS_DIR" --shell /usr/sbin/nologin "$SVC_USER" 2>/dev/null \
        || useradd --system --home-dir "$HBBS_DIR" --shell /sbin/nologin "$SVC_USER"
fi
install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$HBBS_DIR" "$DATA_DIR"

# -- hbbs / hbbr ------------------------------------------------------------------
if [ "$SKIP_RUSTDESK" -eq 0 ]; then
    case "$(uname -m)" in
        x86_64|amd64) ARCH=amd64 ;;
        aarch64|arm64) ARCH=arm64v8 ;;
        armv7l|armv7*) ARCH=armv7 ;;
        i386|i686) ARCH=i386 ;;
        *) die "no hbbs/hbbr build for $(uname -m)" ;;
    esac
    if [ "$RD_VERSION" = latest ]; then
        URL="https://github.com/rustdesk/rustdesk-server/releases/latest/download/rustdesk-server-linux-$ARCH.zip"
    else
        URL="https://github.com/rustdesk/rustdesk-server/releases/download/$RD_VERSION/rustdesk-server-linux-$ARCH.zip"
    fi
    TMP=$(mktemp -d)
    trap 'rm -rf "$TMP"' EXIT
    say "Downloading hbbs/hbbr ($RD_VERSION, $ARCH)"
    fetch "$URL" "$TMP/rd.zip"
    python3 -m zipfile -e "$TMP/rd.zip" "$TMP/x"
    for b in hbbs hbbr; do
        [ -f "$TMP/x/$ARCH/$b" ] || die "$b missing from $URL"
    done
    # Replace binaries of running services safely.
    systemctl stop rustdesk-hbbs rustdesk-hbbr 2>/dev/null || true
    for b in hbbs hbbr rustdesk-utils; do
        [ -f "$TMP/x/$ARCH/$b" ] && install -m 0755 "$TMP/x/$ARCH/$b" "$PREFIX_BIN/$b"
    done
    "$PREFIX_BIN/hbbs" --version

    cat > "$UNIT_DIR/rustdesk-hbbs.service" <<EOF
[Unit]
Description=RustDesk ID/rendezvous server (hbbs)
After=network-online.target
Wants=network-online.target

[Service]
User=$SVC_USER
Group=$SVC_USER
WorkingDirectory=$HBBS_DIR
ExecStart=$PREFIX_BIN/hbbs -r $HOST
Restart=always
RestartSec=3
LimitNOFILE=1000000
UMask=0027
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=$HBBS_DIR

[Install]
WantedBy=multi-user.target
EOF
    cat > "$UNIT_DIR/rustdesk-hbbr.service" <<EOF
[Unit]
Description=RustDesk relay server (hbbr)
After=network-online.target
Wants=network-online.target

[Service]
User=$SVC_USER
Group=$SVC_USER
WorkingDirectory=$HBBS_DIR
ExecStart=$PREFIX_BIN/hbbr
Restart=always
RestartSec=3
LimitNOFILE=1000000
UMask=0027
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=$HBBS_DIR

[Install]
WantedBy=multi-user.target
EOF
fi

# -- RussDesk ---------------------------------------------------------------------
say "Installing RussDesk to $APP_DIR"
rm -rf "$APP_DIR.new"
install -d -m 0755 "$APP_DIR.new"
cp -R "$SRC_DIR/russdesk" "$APP_DIR.new/"
find "$APP_DIR.new" -name __pycache__ -prune -exec rm -rf {} +
chmod -R u=rwX,go=rX "$APP_DIR.new"
rm -rf "$APP_DIR"
mv "$APP_DIR.new" "$APP_DIR"

NEW_PASSWORD=""
if [ ! -f "$ENV_FILE" ]; then
    [ -n "$ADMIN_PASSWORD" ] || ADMIN_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')
    NEW_PASSWORD="$ADMIN_PASSWORD"
    umask 077
    cat > "$ENV_FILE" <<EOF
# RussDesk settings; restart with: systemctl restart russdesk
RUSSDESK_PORT=21114
RUSSDESK_DATA_DIR=$DATA_DIR
RUSSDESK_HBBS_KEY_FILE=$HBBS_DIR/id_ed25519.pub
RUSSDESK_ID_SERVER=$HOST
# Uncomment behind an HTTPS reverse proxy:
# RUSSDESK_TRUST_PROXY=1
# Only used to create the first admin on an empty database:
RUSSDESK_ADMIN_USER=admin
RUSSDESK_ADMIN_PASSWORD=$ADMIN_PASSWORD
EOF
    umask 022
    chown root:"$SVC_USER" "$ENV_FILE"
    chmod 0640 "$ENV_FILE"
else
    echo "Keeping existing $ENV_FILE"
fi

cat > "$UNIT_DIR/russdesk.service" <<EOF
[Unit]
Description=RussDesk web console and API server for RustDesk
After=network-online.target rustdesk-hbbs.service
Wants=network-online.target

[Service]
User=$SVC_USER
Group=$SVC_USER
EnvironmentFile=$ENV_FILE
Environment=PYTHONPATH=$APP_DIR PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WorkingDirectory=$DATA_DIR
ExecStart=$(command -v python3) -m russdesk
Restart=always
RestartSec=3
UMask=0027
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=$DATA_DIR

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
if [ "$SKIP_RUSTDESK" -eq 0 ]; then
    systemctl enable --now rustdesk-hbbr rustdesk-hbbs
    systemctl restart rustdesk-hbbr rustdesk-hbbs
fi
systemctl enable --now russdesk
systemctl restart russdesk

# -- firewall ---------------------------------------------------------------------
if [ "$FIREWALL" -eq 1 ]; then
    if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        say "Opening ports in ufw"
        ufw allow 21114:21119/tcp >/dev/null
        ufw allow 21116/udp >/dev/null
    elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
        say "Opening ports in firewalld"
        firewall-cmd --permanent --add-port=21114-21119/tcp >/dev/null
        firewall-cmd --permanent --add-port=21116/udp >/dev/null
        firewall-cmd --reload >/dev/null
    fi
fi

# -- check ------------------------------------------------------------------------
say "Waiting for services"
KEY=""
i=0
while [ $i -lt 30 ]; do
    if python3 -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:21114/api/login-options", timeout=2)' 2>/dev/null; then
        [ -f "$HBBS_DIR/id_ed25519.pub" ] && KEY=$(cat "$HBBS_DIR/id_ed25519.pub")
        if [ -n "$KEY" ] || [ "$SKIP_RUSTDESK" -eq 1 ]; then break; fi
    fi
    i=$((i + 1))
    sleep 1
done
[ $i -lt 30 ] || { systemctl --no-pager status russdesk rustdesk-hbbs 2>&1 | tail -20; die "services did not come up"; }

echo
echo "RussDesk is running."
echo "  Console:   http://$HOST:21114"
if [ -n "$NEW_PASSWORD" ]; then
    echo "  Login:     admin / $NEW_PASSWORD   (change it under Account)"
fi
echo
echo "Client settings (RustDesk → Settings → Network → ID/Relay server):"
echo "  ID server: $HOST"
echo "  Key:       ${KEY:-(set it in the console: Settings → Server public key)}"
echo "  API server: leave empty"
echo
echo "Open TCP 21114-21119 and UDP 21116 on any firewall in front of this server."
echo "Logs: journalctl -u russdesk -u rustdesk-hbbs -u rustdesk-hbbr -f"
