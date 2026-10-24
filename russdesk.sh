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
#   --ref REF         RussDesk branch or tag to build when not run from a checkout
#                     (default: main, which downloads the latest release binary)
#   --no-firewall     leave ufw/firewalld alone
#   -y, --yes         do not ask questions
#
# RussDesk itself is the Rust server in rust/: a checkout is built with cargo,
# otherwise the matching release binary is downloaded (no Python is used).
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

random_password() {  # 16 letters and digits
    if have openssl; then
        openssl rand -base64 24 | tr -d '/+=\n' | cut -c1-16
    else
        tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 16
        echo
    fi
}

network_cidr() {  # network_cidr 192.168.1.5/24 -> 192.168.1.0/24 (IPv4)
    cidr=$1
    addr=${cidr%/*}
    prefix=${cidr#*/}
    case "$prefix" in ''|*[!0-9]*) echo "$cidr"; return ;; esac
    set -- $(printf '%s' "$addr" | tr '.' ' ')
    [ $# -eq 4 ] || { echo "$cidr"; return; }
    ip=$(( ($1 << 24) + ($2 << 16) + ($3 << 8) + $4 ))
    if [ "$prefix" -eq 0 ]; then mask=0
    else mask=$(( (4294967295 << (32 - prefix)) & 4294967295 )); fi
    net=$(( ip & mask ))
    echo "$(( (net >> 24) & 255 )).$(( (net >> 16) & 255 )).$(( (net >> 8) & 255 )).$(( net & 255 ))/$prefix"
}

extract_zip() {  # extract_zip ARCHIVE DIR
    mkdir -p "$2"
    if have unzip; then unzip -q "$1" -d "$2"; return; fi
    if have busybox; then busybox unzip -q "$1" -d "$2"; return; fi
    say "Installing unzip"
    if have apt-get; then apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unzip >/dev/null
    elif have dnf; then dnf install -y -q unzip >/dev/null
    elif have yum; then yum install -y -q unzip >/dev/null
    elif have zypper; then zypper -nq install unzip >/dev/null
    elif have pacman; then pacman -Sy --noconfirm --needed unzip >/dev/null
    elif have apk; then apk add -q unzip
    fi
    have unzip || die "unzip is required"
    unzip -q "$1" -d "$2"
}

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
        if id "$SVC_USER" >/dev/null 2>&1; then
            pkill -u "$SVC_USER" 2>/dev/null || true  # anything still running as the service user
            i=0
            while pgrep -u "$SVC_USER" >/dev/null 2>&1 && [ $i -lt 10 ]; do sleep 1; i=$((i + 1)); done
            pkill -9 -u "$SVC_USER" 2>/dev/null || true
            userdel "$SVC_USER" 2>/dev/null || echo "warning: could not delete the $SVC_USER user: $(userdel "$SVC_USER" 2>&1)"
        fi
        if getent group "$SVC_USER" >/dev/null 2>&1; then groupdel "$SVC_USER" 2>/dev/null || true; fi
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

# -- reset password ---------------------------------------------------------------

if [ "$CMD" = reset-password ]; then
    [ -x "$APP_DIR/russdesk" ] || die "RussDesk is not installed"
    case "$RESET_USER" in *[!A-Za-z0-9_.-]*) die "invalid user name: $RESET_USER" ;; esac
    pw=$ADMIN_PASSWORD
    if [ -z "$pw" ]; then
        [ -r /dev/tty ] || die "no terminal: pass the new password with --admin-password"
        printf 'New password for %s (8+ characters): ' "$RESET_USER" > /dev/tty
        stty -echo < /dev/tty 2>/dev/null || true
        read -r pw < /dev/tty
        stty echo < /dev/tty 2>/dev/null || true
        echo > /dev/tty
    fi
    printf '%s\n' "$pw" | su -s /bin/sh "$SVC_USER" -c "RUSSDESK_DATA_DIR=$DATA_DIR $APP_DIR/russdesk --reset-password $RESET_USER"
    exit 0
fi

# -- install / upgrade ------------------------------------------------------------

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64; RDESK_ARCH=x86_64 ;;
    aarch64|arm64) ARCH=arm64v8; RDESK_ARCH=aarch64 ;;
    armv7l|armv7*) ARCH=armv7; RDESK_ARCH=armv7 ;;
    i386|i686) ARCH=i386; RDESK_ARCH=i686 ;;
    *) die "no hbbs/hbbr build for $(uname -m)" ;;
esac

build_russdesk() {  # build_russdesk CHECKOUT
    have cargo || die "cargo (Rust 1.75 or newer) is needed to build RussDesk from source: https://rustup.rs"
    say "Building RussDesk with cargo (a few minutes)"
    ( cd "$1/rust" && cargo build --release --locked ) || die "cargo build failed"
    RUSSDESK_BIN="$1/rust/target/release/russdesk"
    STATIC_SRC="$1/rust/static"
}

SRC=""
RUSSDESK_BIN=""
STATIC_SRC=""
if [ -f "$0" ]; then  # run as a file (not piped): use the checkout it lives in
    here=$(cd "$(dirname "$0")" && pwd)
    for d in "$here" "$here/.."; do [ -f "$d/rust/Cargo.toml" ] && SRC=$(cd "$d" && pwd) && break; done
fi
if [ -n "$SRC" ]; then
    build_russdesk "$SRC"
elif [ "$REF" = main ] && { [ "$RDESK_ARCH" = x86_64 ] || [ "$RDESK_ARCH" = aarch64 ]; } \
     && fetch "https://github.com/$REPO/releases/latest/download/russdesk-linux-$RDESK_ARCH.tar.gz" "$TMP/russdesk.tar.gz"; then
    say "Downloaded the RussDesk release binary ($RDESK_ARCH)"
    mkdir -p "$TMP/pkg"
    tar -xzf "$TMP/russdesk.tar.gz" -C "$TMP/pkg"
    RUSSDESK_BIN="$TMP/pkg/russdesk"
    STATIC_SRC="$TMP/pkg/static"
else
    say "Downloading RussDesk source ($REF)"
    fetch "https://codeload.github.com/$REPO/tar.gz/$REF" "$TMP/russdesk.tar.gz"
    mkdir "$TMP/src"
    tar -xzf "$TMP/russdesk.tar.gz" -C "$TMP/src" --strip-components=1
    SRC="$TMP/src"
    build_russdesk "$SRC"
fi
[ -x "$RUSSDESK_BIN" ] || die "the RussDesk binary was not found"
[ -d "$STATIC_SRC" ] || die "the RussDesk static files were not found"

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
        [ -n "$MASK" ] && MASK=$(network_cidr "$MASK")
    fi
elif [ "$LAN" != off ]; then
    MASK=$LAN
fi

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
extract_zip "$TMP/rd.zip" "$TMP/x"
[ -f "$TMP/x/$ARCH/hbbs" ] && [ -f "$TMP/x/$ARCH/hbbr" ] || die "hbbs/hbbr missing from $url"
systemctl stop $SERVICES 2>/dev/null || true
install -d -m 0755 "$BIN_DIR"
install -m 0755 "$TMP/x/$ARCH/hbbs" "$TMP/x/$ARCH/hbbr" "$BIN_DIR/"

say "Installing RussDesk to $APP_DIR"
rm -rf "$APP_DIR.new"
install -d -m 0755 "$APP_DIR.new"
install -m 0755 "$RUSSDESK_BIN" "$APP_DIR.new/russdesk"
cp -R "$STATIC_SRC" "$APP_DIR.new/static"
chmod -R u=rwX,go=rX "$APP_DIR.new"
rm -rf "$APP_DIR"
mv "$APP_DIR.new" "$APP_DIR"

NEW_PASSWORD=""
if [ ! -f "$ENV_FILE" ]; then
    [ -n "$ADMIN_PASSWORD" ] || ADMIN_PASSWORD=$(random_password)
    NEW_PASSWORD=$ADMIN_PASSWORD
    (umask 077; cat > "$ENV_FILE" <<EOF
# RussDesk settings; apply with: systemctl restart russdesk
RUSSDESK_PORT=$API_PORT
RUSSDESK_DATA_DIR=$DATA_DIR
RUSSDESK_STATIC_DIR=$APP_DIR/static
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
WorkingDirectory=$DATA_DIR
ExecStart=$APP_DIR/russdesk
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
until RUSSDESK_PORT=$API_PORT "$APP_DIR/russdesk" --healthcheck 2>/dev/null \
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
