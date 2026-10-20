#!/bin/sh
# RussDesk installer and manager: one script for install, upgrade, status and uninstall.
#
#   curl -fsSL https://raw.githubusercontent.com/nano-rex/russdesk/main/russdesk.sh | sudo sh
#   sudo sh russdesk.sh [install] [options]   install, or upgrade keeping data and settings
#   sudo sh russdesk.sh status                services, addresses and the key for clients
#   sudo sh russdesk.sh uninstall [--purge]   remove RussDesk (--purge: also its data and key)
#   sudo sh russdesk.sh reset-password [USER] new console password for USER (default admin;
#                                             also turns off its 2FA)
#
# Install options:
#   --host ADDR       public DNS name or IP clients use (default: detected public IP)
#   --lan CIDR|off    LAN subnet for devices that reach the server by its LAN address
#                     (default: detected when the server sits on a private network)
#   --admin-password  first console password (default: random, printed once)
#   --rustdesk-version V   hbbs/hbbr release to install (default: latest)
#   --ref REF         RussDesk branch or tag to install when not run from a checkout (default: main)
#   --no-firewall     leave ufw/firewalld alone
#   -y, --yes         do not ask questions
#
# Everything RussDesk creates has its own name, so it can share a machine with RustDesk
# Server Pro or the official rustdesk-server packages:
#   services russdesk, russdesk-hbbs, russdesk-hbbr; user russdesk; ports 31114-31119;
#   /opt/russdesk, /usr/local/lib/russdesk, /var/lib/russdesk, /var/lib/russdesk-hbbs,
#   /etc/russdesk.env, /etc/russdesk-hbbs.env
set -eu

REPO=nano-rex/russdesk
APP_DIR=/opt/russdesk
BIN_DIR=/usr/local/lib/russdesk/bin
DATA_DIR=/var/lib/russdesk
HBBS_DIR=/var/lib/russdesk-hbbs
ENV_FILE=/etc/russdesk.env
HBBS_ENV=/etc/russdesk-hbbs.env
UNIT_DIR=/etc/systemd/system
SVC_USER=russdesk
SERVICES="russdesk russdesk-hbbs russdesk-hbbr"
API_PORT=31114
ID_PORT=31116
RELAY_PORT=31117

die() { echo "error: $*" >&2; exit 1; }
say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() { awk 'NR > 1 && /^set -eu/ { exit } NR > 1' "$0" 2>/dev/null | sed 's/^# \{0,1\}//' ||
          echo "See https://github.com/$REPO"; }

CMD=install
case "${1:-}" in
    install|upgrade|status|uninstall|reset-password) CMD=$1; shift ;;
    -h|--help|help) usage; exit 0 ;;
esac

HOST="" LAN="auto" ADMIN_PASSWORD="" RD_VERSION="latest" REF="main" FIREWALL=1 YES=0 PURGE=0 RESET_USER=admin
while [ $# -gt 0 ]; do
    case "$1" in
        --host) HOST="${2:?--host needs a value}"; shift 2 ;;
        --lan) LAN="${2:?--lan needs a value}"; shift 2 ;;
        --admin-password) ADMIN_PASSWORD="${2:?}"; shift 2 ;;
        --rustdesk-version) RD_VERSION="${2:?}"; shift 2 ;;
        --ref) REF="${2:?}"; shift 2 ;;
        --no-firewall) FIREWALL=0; shift ;;
        --purge) PURGE=1; shift ;;
        -y|--yes) YES=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) if [ "$CMD" = reset-password ] && [ "${1#-}" = "$1" ]; then RESET_USER=$1; shift
           else die "unknown option: $1 (see --help)"; fi ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "run as root, e.g.: sudo sh $0 $CMD"
have systemctl || die "systemd is required"

# Questions go to the terminal even when the script itself comes from a pipe.
ask() {  # ask "question" default -> answer
    if [ "$YES" -eq 1 ] || [ ! -r /dev/tty ]; then echo "$2"; return; fi
    printf '%s [%s] ' "$1" "$2" > /dev/tty
    read -r reply < /dev/tty || reply=""
    echo "${reply:-$2}"
}

fetch() {  # fetch URL FILE
    if have curl; then curl -fsSL --retry 3 -o "$2" "$1"
    elif have wget; then wget -q -O "$2" "$1"
    else die "curl or wget is required"; fi
}

fetch_text() {  # fetch_text URL -> body (empty on failure)
    if have curl; then curl -4 -fsS -m 6 "$1" 2>/dev/null || true
    elif have wget; then wget -4 -q -T 6 -O - "$1" 2>/dev/null || true; fi
}

public_ip() {  # the address the internet sees, from the first service that answers
    for u in https://ifconfig.me https://icanhazip.com https://checkip.amazonaws.com https://api.ipify.org; do
        ip=$(fetch_text "$u" | tr -dc '0-9.')
        case "$ip" in *.*.*.*) echo "$ip"; return ;; esac
    done
}

# -- firewall ---------------------------------------------------------------------

firewall() {  # firewall open|close
    [ "$FIREWALL" -eq 1 ] || return 0
    if have ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
        if [ "$1" = open ]; then
            say "Opening ports $API_PORT-31119/tcp and $ID_PORT/udp in ufw"
            ufw allow 31114:31119/tcp comment russdesk >/dev/null
            ufw allow $ID_PORT/udp comment russdesk >/dev/null
        else
            say "Closing RussDesk's ports in ufw"
            ufw delete allow 31114:31119/tcp >/dev/null 2>&1 || true
            ufw delete allow $ID_PORT/udp >/dev/null 2>&1 || true
        fi
    elif have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
        op=$([ "$1" = open ] && echo add || echo remove)
        say "$( [ "$1" = open ] && echo Opening || echo Closing ) RussDesk's ports in firewalld"
        firewall-cmd --permanent --$op-port=31114-31119/tcp >/dev/null 2>&1 || true
        firewall-cmd --permanent --$op-port=$ID_PORT/udp >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null
    elif [ "$1" = open ] && [ -f /etc/csf/csf.conf ]; then
        echo "note: CSF firewall detected; add 31114:31119 to TCP_IN and 31116 to UDP_IN yourself."
    fi
}

# -- uninstall --------------------------------------------------------------------

if [ "$CMD" = uninstall ]; then
    if [ "$PURGE" -eq 1 ]; then
        echo "This removes RussDesk and DELETES its data: users, devices, logs, address books,"
        echo "and the server key in $HBBS_DIR (clients would need the new key after a reinstall)."
    else
        echo "This removes RussDesk's services, programs and firewall rules."
        echo "Data, settings and the server key stay in $DATA_DIR, $HBBS_DIR and $ENV_FILE."
    fi
    case "$(ask "Continue? (yes/no)" yes)" in y|Y|yes|YES) ;; *) echo "Cancelled."; exit 1 ;; esac
    say "Stopping and removing services"
    for s in $SERVICES; do
        systemctl disable --now "$s" >/dev/null 2>&1 || true
        rm -f "$UNIT_DIR/$s.service"
    done
    systemctl daemon-reload
    rm -rf "$APP_DIR" /usr/local/lib/russdesk
    firewall close
    if [ "$PURGE" -eq 1 ]; then
        say "Deleting data, settings and the russdesk user"
        rm -rf "$DATA_DIR" "$HBBS_DIR" "$ENV_FILE" "$HBBS_ENV"
        if id "$SVC_USER" >/dev/null 2>&1; then userdel "$SVC_USER" 2>/dev/null || true; fi
        echo "RussDesk is completely removed."
    else
        echo "RussDesk is removed. Reinstall to pick up the kept data, or run: sudo sh $0 uninstall --purge"
    fi
    exit 0
fi

# -- status -----------------------------------------------------------------------

env_value() { [ -f "$1" ] && sed -n "s/^$2=//p" "$1" | tail -1; }

show_status() {
    for s in $SERVICES; do printf '  %-15s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null || true)"; done
    id_server=$(env_value "$ENV_FILE" RUSSDESK_ID_SERVER)
    key=$(cat "$HBBS_DIR/id_ed25519.pub" 2>/dev/null || true)
    lan_ip=$(env_value "$HBBS_ENV" LOCAL_IP | cut -d: -f1)
    echo
    echo "  Console:     http://${id_server%:*}:$API_PORT"
    echo "  ID server:   ${id_server:-?}"
    [ -n "$lan_ip" ] && echo "               $lan_ip:$ID_PORT for devices on the server's own LAN"
    echo "  Key:         ${key:-?}"
    echo "  API server:  leave empty in clients"
    echo
    echo "  Logs: journalctl -u russdesk -u russdesk-hbbs -u russdesk-hbbr -f"
}

if [ "$CMD" = status ]; then
    [ -f "$ENV_FILE" ] || die "RussDesk is not installed"
    show_status
    exit 0
fi

# -- python -----------------------------------------------------------------------

find_python() {
    for p in python3.14 python3.13 python3.12 python3.11 python3.10 python3; do
        if have "$p" && "$p" -c 'import sys, sqlite3; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; then
            command -v "$p"; return 0
        fi
    done
    return 1
}

PY=$(find_python || true)
if [ -z "$PY" ] && [ "$CMD" != reset-password ]; then
    say "Python 3.10 or newer is needed; installing it"
    if have apt-get; then apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 >/dev/null
    elif have dnf; then dnf install -y -q python3.11 >/dev/null 2>&1 || dnf install -y -q python3 >/dev/null
    elif have yum; then yum install -y -q python3.11 >/dev/null 2>&1 || yum install -y -q python3 >/dev/null
    elif have zypper; then zypper -nq install python311 >/dev/null 2>&1 || zypper -nq install python3 >/dev/null
    elif have pacman; then pacman -Sy --noconfirm --needed python >/dev/null
    elif have apk; then apk add -q python3
    fi
    PY=$(find_python || true)
    [ -n "$PY" ] || die "could not find or install Python 3.10+; install it and run again"
fi

if [ "$CMD" = reset-password ]; then
    [ -d "$APP_DIR/russdesk" ] || die "RussDesk is not installed"
    PY=$(find_python) || die "Python 3.10+ not found"
    pw=$ADMIN_PASSWORD
    if [ -z "$pw" ]; then
        [ -r /dev/tty ] || die "no terminal: pass the new password with --admin-password"
        printf 'New password for %s (8+ characters): ' "$RESET_USER" > /dev/tty
        stty -echo < /dev/tty 2>/dev/null || true
        read -r pw < /dev/tty
        stty echo < /dev/tty 2>/dev/null || true
        echo > /dev/tty
    fi
    printf '%s\n' "$pw" | su -s /bin/sh "$SVC_USER" -c "cd $DATA_DIR && RUSSDESK_DATA_DIR=$DATA_DIR PYTHONPATH=$APP_DIR $PY -m russdesk --reset-password $RESET_USER"
    exit 0
fi

# -- install / upgrade ------------------------------------------------------------

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Source: the checkout this script lives in, or a download from GitHub.
SRC=""
if [ -f "$0" ]; then  # run as a file (not piped): use the checkout it lives in
    here=$(cd "$(dirname "$0")" && pwd)
    for d in "$here" "$here/.."; do [ -f "$d/russdesk/__main__.py" ] && SRC=$(cd "$d" && pwd) && break; done
fi
if [ -z "$SRC" ]; then
    say "Downloading RussDesk ($REF)"
    fetch "https://codeload.github.com/$REPO/tar.gz/$REF" "$TMP/russdesk.tar.gz"
    mkdir "$TMP/src"
    tar -xzf "$TMP/russdesk.tar.gz" -C "$TMP/src" --strip-components=1
    SRC="$TMP/src"
fi
[ -f "$SRC/russdesk/__main__.py" ] || die "RussDesk source not found"

UPGRADE=0
[ -f "$ENV_FILE" ] && UPGRADE=1

is_private() {  # is_private IP
    case "$1" in
        10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0 ;;
    esac
    return 1
}

LOCAL_ADDR=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)
[ -n "$LOCAL_ADDR" ] || LOCAL_ADDR=$(hostname -I 2>/dev/null | awk '{print $1}')

if [ -z "$HOST" ] && [ "$UPGRADE" -eq 1 ]; then
    HOST=$(env_value "$ENV_FILE" RUSSDESK_ID_SERVER | sed 's/:[0-9]*$//')
fi
if [ -z "$HOST" ]; then
    detected=""
    if is_private "${LOCAL_ADDR:-10.}"; then
        detected=$(public_ip)
    fi
    HOST=$(ask "Address clients use to reach this server" "${detected:-$LOCAL_ADDR}")
fi
[ -n "$HOST" ] || die "could not detect an address; pass --host"

# LAN mode: a server behind NAT whose router may not loop public traffic back
# in. hbbs then hands LAN devices the LAN relay address (MASK / LOCAL_IP).
MASK=""
if [ "$LAN" = auto ]; then
    if [ "$UPGRADE" -eq 1 ] && [ -f "$HBBS_ENV" ]; then
        MASK=$(env_value "$HBBS_ENV" MASK)
    elif is_private "${LOCAL_ADDR:-x}" && [ "$HOST" != "$LOCAL_ADDR" ]; then
        MASK=$(ip -o -4 addr show 2>/dev/null | awk -v a="$LOCAL_ADDR" '{split($4, p, "/"); if (p[1] == a) print $4}' | head -1)
        [ -n "$MASK" ] && MASK=$("$PY" -c 'import ipaddress, sys; print(ipaddress.ip_interface(sys.argv[1]).network)' "$MASK")
    fi
elif [ "$LAN" != off ]; then
    MASK=$LAN
fi

case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64v8 ;;
    armv7l|armv7*) ARCH=armv7 ;;
    i386|i686) ARCH=i386 ;;
    *) die "no hbbs/hbbr build for $(uname -m)" ;;
esac

say "$( [ "$UPGRADE" -eq 1 ] && echo Upgrading || echo Installing ) RussDesk for $HOST"

if ! id "$SVC_USER" >/dev/null 2>&1; then
    say "Creating system user $SVC_USER"
    useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$SVC_USER" 2>/dev/null ||
        useradd --system --home-dir "$DATA_DIR" --shell /sbin/nologin "$SVC_USER"
fi
install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$DATA_DIR" "$HBBS_DIR"

# hbbs / hbbr: the official open-source release
if [ "$RD_VERSION" = latest ]; then
    url="https://github.com/rustdesk/rustdesk-server/releases/latest/download/rustdesk-server-linux-$ARCH.zip"
else
    url="https://github.com/rustdesk/rustdesk-server/releases/download/$RD_VERSION/rustdesk-server-linux-$ARCH.zip"
fi
say "Downloading hbbs/hbbr ($RD_VERSION, $ARCH)"
fetch "$url" "$TMP/rd.zip"
"$PY" -m zipfile -e "$TMP/rd.zip" "$TMP/x"
[ -f "$TMP/x/$ARCH/hbbs" ] && [ -f "$TMP/x/$ARCH/hbbr" ] || die "hbbs/hbbr missing from $url"
systemctl stop $SERVICES 2>/dev/null || true
install -d -m 0755 "$BIN_DIR"
install -m 0755 "$TMP/x/$ARCH/hbbs" "$TMP/x/$ARCH/hbbr" "$BIN_DIR/"

say "Installing RussDesk to $APP_DIR"
rm -rf "$APP_DIR.new"
install -d -m 0755 "$APP_DIR.new"
cp -R "$SRC/russdesk" "$APP_DIR.new/"
[ -d "$SRC/tools" ] && cp -R "$SRC/tools" "$APP_DIR.new/"
find "$APP_DIR.new" -name __pycache__ -prune -exec rm -rf {} +
chmod -R u=rwX,go=rX "$APP_DIR.new"
rm -rf "$APP_DIR"
mv "$APP_DIR.new" "$APP_DIR"

NEW_PASSWORD=""
if [ ! -f "$ENV_FILE" ]; then
    [ -n "$ADMIN_PASSWORD" ] || ADMIN_PASSWORD=$("$PY" -c 'import secrets; print(secrets.token_urlsafe(12))')
    NEW_PASSWORD=$ADMIN_PASSWORD
    (umask 077; cat > "$ENV_FILE" <<EOF
# RussDesk settings; apply with: systemctl restart russdesk
RUSSDESK_PORT=$API_PORT
RUSSDESK_DATA_DIR=$DATA_DIR
RUSSDESK_HBBS_KEY_FILE=$HBBS_DIR/id_ed25519.pub
RUSSDESK_ID_SERVER=$HOST:$ID_PORT
# Uncomment behind an HTTPS reverse proxy:
# RUSSDESK_TRUST_PROXY=1
# Only used to create the first admin on an empty database:
RUSSDESK_ADMIN_USER=admin
RUSSDESK_ADMIN_PASSWORD=$ADMIN_PASSWORD
EOF
)
else
    sed -i -e "s|^RUSSDESK_PORT=21114\$|RUSSDESK_PORT=$API_PORT|" \
        -e "s|^RUSSDESK_ID_SERVER=.*|RUSSDESK_ID_SERVER=$HOST:$ID_PORT|" \
        -e "s|^RUSSDESK_HBBS_KEY_FILE=/var/lib/rustdesk-server/|RUSSDESK_HBBS_KEY_FILE=$HBBS_DIR/|" "$ENV_FILE"
fi
chown root:"$SVC_USER" "$ENV_FILE"
chmod 0640 "$ENV_FILE"

{
    echo "# hbbs settings written by russdesk.sh; re-run it to change them"
    echo "RELAY=$HOST:$RELAY_PORT"
    [ -n "$MASK" ] && echo "MASK=$MASK" && echo "LOCAL_IP=$LOCAL_ADDR:$RELAY_PORT"
    true
} > "$HBBS_ENV"
chmod 0644 "$HBBS_ENV"
# hbbs only reads "local-ip" from its .env file (the name has a dash, which
# systemd environment files cannot carry).
if [ -n "$MASK" ]; then
    printf 'mask=%s\nlocal-ip=%s:%s\n' "$MASK" "$LOCAL_ADDR" "$RELAY_PORT" > "$HBBS_DIR/.env"
    chmod 0644 "$HBBS_DIR/.env"
else
    rm -f "$HBBS_DIR/.env"
fi

hardening="NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
UMask=0027
Restart=always
RestartSec=3"

cat > "$UNIT_DIR/russdesk-hbbs.service" <<EOF
[Unit]
Description=RussDesk: RustDesk ID/rendezvous server (hbbs, port $ID_PORT)
After=network-online.target
Wants=network-online.target

[Service]
User=$SVC_USER
Group=$SVC_USER
WorkingDirectory=$HBBS_DIR
Environment=HOME=$HBBS_DIR
EnvironmentFile=$HBBS_ENV
ExecStart=$BIN_DIR/hbbs -p $ID_PORT -r \${RELAY}
LimitNOFILE=1000000
ReadWritePaths=$HBBS_DIR
$hardening

[Install]
WantedBy=multi-user.target
EOF

cat > "$UNIT_DIR/russdesk-hbbr.service" <<EOF
[Unit]
Description=RussDesk: RustDesk relay server (hbbr, port $RELAY_PORT)
After=network-online.target
Wants=network-online.target

[Service]
User=$SVC_USER
Group=$SVC_USER
WorkingDirectory=$HBBS_DIR
Environment=HOME=$HBBS_DIR
ExecStart=$BIN_DIR/hbbr -p $RELAY_PORT
LimitNOFILE=1000000
ReadWritePaths=$HBBS_DIR
$hardening

[Install]
WantedBy=multi-user.target
EOF

cat > "$UNIT_DIR/russdesk.service" <<EOF
[Unit]
Description=RussDesk web console and API server (port $API_PORT)
After=network-online.target russdesk-hbbs.service
Wants=network-online.target

[Service]
User=$SVC_USER
Group=$SVC_USER
EnvironmentFile=$ENV_FILE
Environment=PYTHONPATH=$APP_DIR PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WorkingDirectory=$DATA_DIR
ExecStart=$PY -m russdesk
ReadWritePaths=$DATA_DIR
$hardening

[Install]
WantedBy=multi-user.target
EOF

# Installs before v0.2.1 used other service names and paths; retire them.
for old in rustdesk-hbbs rustdesk-hbbr; do
    if grep -qs "RussDesk" "$UNIT_DIR/$old.service"; then
        systemctl disable --now "$old" >/dev/null 2>&1 || true
        rm -f "$UNIT_DIR/$old.service"
    fi
done

systemctl daemon-reload
systemctl enable --now $SERVICES >/dev/null 2>&1
systemctl restart $SERVICES
firewall open

say "Checking the services"
i=0
until "$PY" -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:$API_PORT/api/login-options', timeout=2)" 2>/dev/null \
      && [ -s "$HBBS_DIR/id_ed25519.pub" ]; do
    i=$((i + 1))
    if [ $i -ge 30 ]; then
        systemctl --no-pager status $SERVICES 2>&1 | tail -25
        die "services did not come up"
    fi
    sleep 1
done

echo
echo "RussDesk is $( [ "$UPGRADE" -eq 1 ] && echo upgraded || echo running )."
[ -n "$NEW_PASSWORD" ] && echo "  Login:       admin / $NEW_PASSWORD   (change it under Account)"
show_status
echo "  Open TCP 31114-31119 and UDP 31116 on any firewall or router in front of this server."
if [ -n "$MASK" ]; then
    echo "  LAN mode: devices in $MASK are sent to the relay at $LOCAL_ADDR:$RELAY_PORT."
fi
