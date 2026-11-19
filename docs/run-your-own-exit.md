# Run your own exit

An exit is a Linux box that Session Router clients, including Rusty on
Windows, can send their traffic through. You give people the exit's `.sesh`
address, and they map it with `rusty-ctl map <exit>.sesh --full`.

Traffic that leaves the exit comes from your VPS's IP address. You are
responsible for it. The firewall below only allows web (TCP 80 and 443) and
DNS (UDP and TCP 53), and rate-limits them, but that is still enough for
someone to misuse the exit. If you do not set an allow list, anyone on the
network can use it.

## What you need

- A Linux VPS with a public IPv4 address. Ubuntu or Debian is fine.
- Root access.
- A couple of GB of RAM if you compile on the VPS itself (you can also
  compile on another machine and copy `session-router` and
  `session-router-config` over).

## Build the router

The router lives in `router/` in this repo. On Ubuntu or Debian:

```
sudo apt update
sudo apt install build-essential cmake git pkg-config automake libtool \
  libcap-dev libcap2-bin nftables libssl-dev libsodium-dev libzmq3-dev \
  libunbound-dev libevent-dev libzstd-dev libcurl4-openssl-dev nettle-dev \
  nlohmann-json3-dev libuv1-dev libsystemd-dev libgnutls28-dev
```

Then, from a clone of this repo:

```
cmake -S router -B router/build -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DSUBMODULE_CHECK=OFF
cmake --build router/build -j$(nproc) --target session-router session-router-config
sudo cmake --install router/build
```

That installs `session-router` and `session-router-config` to `/usr/local/bin`.

## Key and config

```
sudo mkdir -p /opt/session-router-exit/data
sudo session-router-config -k /opt/session-router-exit/exit.key
sudo chmod 600 /opt/session-router-exit/exit.key
```

`session-router-config -k` prints the exit's `.sesh` address. That is what
you give clients. To see it again later:

```
sudo session-router-config -s /opt/session-router-exit/exit.key
```

Never share `exit.key`.

Write `/opt/session-router-exit/exit.ini`:

```
[router]
data-dir=/opt/session-router-exit/data

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
keyfile=/opt/session-router-exit/exit.key
ifname=sr-tun-exit
ifaddr=10.193.0.1/16
reachable=true
auto-routing=false
blackhole-routes=false
# Optional. Without these two lines, anyone can use the exit.
# auth-type=whitelist
# auth-whitelist=their-address.sesh

[api]
enabled=true
bind=ipc:///opt/session-router-exit/exit-rpc.sock

[bind]
listen=:1090

[dns]
listen=127.0.0.1:29153
```

To allow only people you know, uncomment `auth-type` and `auth-whitelist`, and
put each client's `.sesh` address on its own `auth-whitelist=` line. On
Windows they get that address from `my-client-address.txt` (they should never
send you `client.key`). Restart the service after you change the list.

## Firewall and forwarding

The router does not set up internet forwarding for you. Turn on IP forwarding,
open UDP 1090 for the router itself, and only forward web and DNS from the
tunnel, with rate limits. Everything else from the tunnel is dropped, including
traffic to private address ranges.

Replace `eth0` with your public interface. `ip route show default` tells you
the name; it is often `eth0`, `enp1s0`, or `ens3`.

```
echo net.ipv4.ip_forward=1 | sudo tee /etc/sysctl.d/90-session-router-exit.conf
sudo sysctl -w net.ipv4.ip_forward=1
```

Save this as `/opt/session-router-exit/fw.nft`, with your interface name in
place of `eth0`, then load it with `sudo nft -f /opt/session-router-exit/fw.nft`:

```
table inet session_router_exit
delete table inet session_router_exit
table inet session_router_exit {
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
    udp dport 1090 accept
    icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 10/second accept
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    oifname "sr-tun-exit" ct state established,related accept
    iifname "sr-tun-exit" ip daddr @blocked4 drop
    iifname "sr-tun-exit" meta nfproto ipv6 drop
    iifname "sr-tun-exit" oifname "eth0" meta l4proto { tcp, udp } th dport 53 update @dnsfwd_rl4 { ip saddr limit rate over 100/second burst 200 packets } drop
    iifname "sr-tun-exit" oifname "eth0" meta l4proto { tcp, udp } th dport 53 counter accept
    iifname "sr-tun-exit" oifname "eth0" tcp dport { 80, 443 } ct state new update @web_rl4 { ip saddr limit rate over 50/second burst 100 packets } drop
    iifname "sr-tun-exit" oifname "eth0" tcp dport { 80, 443 } counter accept
  }
  chain postrouting {
    type nat hook postrouting priority 100;
    ip saddr 10.193.0.0/16 oifname "eth0" counter masquerade
  }
}
```

The file creates the table, deletes it, then creates it again, so you can
reload it safely. The input policy is drop, so only SSH and UDP 1090 are
allowed in. If this VPS also runs other services, add rules for those
ports before you load the file.

If ufw is on (it often is, on Ubuntu, and its default is to refuse forwarded
traffic), also allow the same things, or ufw will drop them even when nft
allows them:

```
sudo ufw allow 1090/udp comment 'session router'
sudo ufw route allow in on sr-tun-exit out on eth0 proto tcp to any port 80,443 comment 'session router exit web'
sudo ufw route allow in on sr-tun-exit out on eth0 proto udp to any port 53 comment 'session router exit dns fwd'
sudo ufw route allow in on sr-tun-exit out on eth0 proto tcp to any port 53 comment 'session router exit dns fwd'
```

## Run it as a service

`/etc/systemd/system/session-router-exit-fw.service`:

```
[Unit]
Description=Session Router exit firewall and NAT
Before=session-router-exit.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /opt/session-router-exit/fw.nft
ExecStop=/usr/sbin/nft delete table inet session_router_exit

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/session-router-exit.service`:

```
[Unit]
Description=Session Router exit
After=network-online.target session-router-exit-fw.service
Requires=session-router-exit-fw.service

[Service]
ExecStart=/usr/local/bin/session-router /opt/session-router-exit/exit.ini
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

If the binary ended up at `/usr/bin/session-router` instead, use that path.

```
sudo systemctl daemon-reload
sudo systemctl enable --now session-router-exit-fw session-router-exit
```

Give it a little time to join the network, then hand out the `.sesh` address
from `session-router-config -s`. On the Windows client:

```
.\rusty-ctl.exe map <exit>.sesh --full
.\rusty-ctl.exe exits
```

Wait for `session to exit: live` and `exit routes: up`.

`scripts/exit-setup.sh` writes these files for you, fills in the public
interface name, and can apply the firewall and units. It does not build the
router. Run it as root after `session-router` is installed:

```
sudo ./scripts/exit-setup.sh --apply
```

Without `--apply` it only writes the files and prints the next steps.
