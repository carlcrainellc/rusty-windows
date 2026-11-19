# Changes in this copy of Session Router

This directory is a modified copy of Session Router
(<https://github.com/session-foundation/session-router>, GPL-3.0-or-later), taken from
upstream commit `afb98f959` (September 2026) together with the third-party sources it
pulls in as submodules, so it builds without network access to those repositories.
The `gui/` submodule and upstream CI files are left out.

Changed for Windows (MinGW cross-build), 2026-09 to 2026-11:

- **MinGW build fixes:** Winsock headers and macros (`dns/rr.hpp`, `net/ip_headers.hpp`,
  `net/policy.cpp`, `ev/tcp.hpp`, `messages/common.hpp`, `win32/*`), static libzstd
  linking for the daemon (`src/daemon/CMakeLists.txt`, `zstd_trace_stubs.c`), and
  dependency recipes in `cmake/session-deps`, `external/oxen-mq` (bundled libzmq, built
  without IPC on MinGW) and
  `external/oxen-libquic` (`IP_ECN` on MinGW).
- **Wintun and routes:** updated Wintun API use, IPv4/IPv6 route management through the
  Windows route table (`vpn/win32.cpp`, `net/win32.cpp`), the TUN drain timer used
  instead of an FD poller on Windows (`handlers/tun.*`).
- **Exits at runtime:** `map_exit`, `unmap_exit`, `list_exits` and `swap_exits` RPC
  calls (`rpc/*`), with full-tunnel routes put up and taken down as exits are mapped
  (`router/route_poker.*`, `router/router.*`, `handlers/tun.*`, `session/*`,
  `link/endpoint.*`).
- **First-hop routes:** relays are pinned through the gateway Windows actually uses
  (best default route by route + interface metric, adapter up, never the TUN), and
  re-checked every few seconds while routes are up.
- **No local traffic into the exit:** with a full-tunnel exit, private, link-local,
  loopback, multicast, broadcast and reserved destinations stay local, except the
  configured DNS upstream.
- No `127.0.0.0/8` route hole is added to the TUN.
