#!/bin/bash
# Write a Session Router exit config, nft firewall, and systemd units.
# Run as root on the exit VPS after session-router is installed.
# Without --apply, only writes files under --dir and prints the next steps.
set -euo pipefail

DIR=/opt/session-router-exit
IFACE=
APPLY=0

usage() {
  cat <<'USAGE'
Usage: exit-setup.sh [--dir /opt/session-router-exit] [--iface eth0] [--apply]

Writes exit.ini, fw.nft, and systemd units for a web+DNS-only exit.
Detects the public interface from the default route unless --iface is set.

  --apply   also install the units, enable IP forwarding, load the
            firewall, add matching ufw rules if ufw is active, and start
            the services (needs root, and session-router on PATH)
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dir)
      DIR=${2:?--dir needs a path}
      shift 2
      ;;
    --iface)
      IFACE=${2:?--iface needs an interface name}
      shift 2
      ;;
    --apply)
      APPLY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [ -z "$IFACE" ]; then
  IFACE=$(ip -4 route show default 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i+1); exit }}')
fi
if [ -z "$IFACE" ]; then
  echo "could not detect the public interface; pass --iface" >&2
  exit 1
fi
if ! [[ "$IFACE" =~ ^[a-zA-Z0-9._-]+$ ]]; then
  echo "invalid interface name: $IFACE" >&2
  exit 1
fi

TUN_IF=sr-tun-exit
TUN_ADDR=10.193.0.1/16
TUN_NET=10.193.0.0/16
TABLE=session_router_exit
LISTEN_PORT=1090

find_bin() {
  local name="$1"
  if command -v "$name" >/dev/null 2>&1; then
    command -v "$name"
    return
  fi
  local p
  for p in /usr/local/bin/"$name" /usr/bin/"$name"; do
    if [ -x "$p" ]; then
      printf '%s\n' "$p"
      return
    fi
  done
  return 1
}

ROUTER_BIN=$(find_bin session-router || true)
CONFIG_BIN=$(find_bin session-router-config || true)
NFT_BIN=$(find_bin nft || true)
[ -n "$NFT_BIN" ] || NFT_BIN=/usr/sbin/nft

umask 022
mkdir -p "$DIR/data"

if [ ! -e "$DIR/exit.key" ]; then
  if [ -n "$CONFIG_BIN" ]; then
    "$CONFIG_BIN" -k "$DIR/exit.key"
    chmod 600 "$DIR/exit.key"
  else
    echo "no exit.key yet, and session-router-config is not installed."
    echo "Build the router, then run: session-router-config -k $DIR/exit.key"
  fi
elif [ -n "$CONFIG_BIN" ]; then
  echo "keeping existing $DIR/exit.key"
  "$CONFIG_BIN" -s "$DIR/exit.key"
fi

cat > "$DIR/exit.ini" <<INI
[router]
data-dir=$DIR/data

[logging]
level=info

[exit]
enable=true
routed-range=public
policy=tcp/443
policy=tcp/80
policy=udp/53
policy=tcp/53

[network]
keyfile=$DIR/exit.key
ifname=$TUN_IF
ifaddr=$TUN_ADDR
reachable=true
auto-routing=false
blackhole-routes=false
# Optional. Without these two lines, anyone can use the exit.
# auth-type=whitelist
# auth-whitelist=their-address.sesh

[api]
enabled=true
bind=ipc://$DIR/exit-rpc.sock

[bind]
listen=:$LISTEN_PORT

[dns]
listen=127.0.0.1:29153
INI

cat > "$DIR/fw.nft" <<NFT
table inet $TABLE
delete table inet $TABLE
table inet $TABLE {
  set blocked4 {
    type ipv4_addr; flags interval
    elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12,
                 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/3 }
  }
  set dnsfwd_rl4 { type ipv4_addr; size 65535; flags dynamic,timeout; timeout 1m; }
  set web_rl4 { type ipv4_addr; size 65535; flags dynamic,timeout; timeout 1m; }
  chain input {
    type filter hook input priority 0; policy drop;
    iif "lo" accept
    ct state established,related accept
    tcp dport 22 accept
    udp dport $LISTEN_PORT accept
    icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 10/second accept
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    oifname "$TUN_IF" ct state established,related accept
    iifname "$TUN_IF" ip daddr @blocked4 drop
    iifname "$TUN_IF" meta nfproto ipv6 drop
    iifname "$TUN_IF" oifname "$IFACE" meta l4proto { tcp, udp } th dport 53 update @dnsfwd_rl4 { ip saddr limit rate over 100/second burst 200 packets } drop
    iifname "$TUN_IF" oifname "$IFACE" meta l4proto { tcp, udp } th dport 53 counter accept
    iifname "$TUN_IF" oifname "$IFACE" tcp dport { 80, 443 } ct state new update @web_rl4 { ip saddr limit rate over 50/second burst 100 packets } drop
    iifname "$TUN_IF" oifname "$IFACE" tcp dport { 80, 443 } counter accept
  }
  chain postrouting {
    type nat hook postrouting priority 100;
    ip saddr $TUN_NET oifname "$IFACE" counter masquerade
  }
}
NFT

cat > "$DIR/90-session-router-exit.conf" <<SYSCTL
net.ipv4.ip_forward = 1
SYSCTL

ROUTER_PATH=${ROUTER_BIN:-/usr/local/bin/session-router}

cat > "$DIR/session-router-exit-fw.service" <<UNIT
[Unit]
Description=Session Router exit firewall and NAT
Before=session-router-exit.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$NFT_BIN -f $DIR/fw.nft
ExecStop=$NFT_BIN delete table inet $TABLE

[Install]
WantedBy=multi-user.target
UNIT

cat > "$DIR/session-router-exit.service" <<UNIT
[Unit]
Description=Session Router exit
After=network-online.target session-router-exit-fw.service
Requires=session-router-exit-fw.service

[Service]
ExecStart=$ROUTER_PATH $DIR/exit.ini
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

echo "wrote config and units in $DIR (public interface: $IFACE)"

if [ "$APPLY" -eq 0 ]; then
  cat <<NEXT

Files are ready. As root, to apply them:

  cp $DIR/90-session-router-exit.conf /etc/sysctl.d/
  sysctl -w net.ipv4.ip_forward=1
  $NFT_BIN -f $DIR/fw.nft
  cp $DIR/session-router-exit-fw.service $DIR/session-router-exit.service /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now session-router-exit-fw session-router-exit

If ufw is on, also allow UDP $LISTEN_PORT in, and forwarded TCP 80,443 plus
UDP/TCP 53 from $TUN_IF out $IFACE. Or run this script again with --apply.

NEXT
  exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "--apply needs root" >&2
  exit 1
fi
if [ ! -x "$NFT_BIN" ]; then
  echo "nft not found; install the nftables package" >&2
  exit 1
fi
if [ ! -x "$ROUTER_PATH" ]; then
  echo "session-router not found at $ROUTER_PATH; build and install the router first" >&2
  exit 1
fi
if [ ! -f "$DIR/exit.key" ]; then
  echo "missing $DIR/exit.key; run: session-router-config -k $DIR/exit.key" >&2
  exit 1
fi

cp "$DIR/90-session-router-exit.conf" /etc/sysctl.d/90-session-router-exit.conf
sysctl -w net.ipv4.ip_forward=1
# fw.nft creates an empty table first so 'delete table' works on a fresh host.
$NFT_BIN -f "$DIR/fw.nft"
cp "$DIR/session-router-exit-fw.service" "$DIR/session-router-exit.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now session-router-exit-fw session-router-exit

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
  ufw allow "$LISTEN_PORT"/udp comment 'session router'
  ufw route allow in on "$TUN_IF" out on "$IFACE" proto tcp to any port 80,443 comment 'session router exit web'
  ufw route allow in on "$TUN_IF" out on "$IFACE" proto udp to any port 53 comment 'session router exit dns fwd'
  ufw route allow in on "$TUN_IF" out on "$IFACE" proto tcp to any port 53 comment 'session router exit dns fwd'
  echo "added matching ufw rules (ufw is active)"
fi

echo "exit is enabled. Give clients the .sesh address from: session-router-config -s $DIR/exit.key"
