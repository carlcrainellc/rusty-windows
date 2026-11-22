# Router RPC calls used

The router listens with OxenMQ on `tcp://127.0.0.1:1190` (`[api] bind=`). Requests are
`[command, tag, json]`; replies are `["REPLY", tag, json]` with `{"result": ...}` or
`{"error": "..."}`. Commands in the `llarp.` category need admin, which the router gives
to loopback connections only.

| Call | Arguments | Used by |
| --- | --- | --- |
| `llarp.version` | none | `rusty-ctl status`, service readiness check |
| `llarp.list_exits` | none | `rusty-ctl status`, `rusty-ctl exits` |
| `llarp.map_exit` | `address`, `full_tunnel`, `ip_ranges`, `token` | `rusty-ctl map` |
| `llarp.unmap_exit` | `address` | `rusty-ctl unmap` (with no address: each exit from `list_exits`) |
| `llarp.swap_exits` | `exit_addresses` (old, new), `full_tunnel`, `ip_ranges`, `token` | `rusty-ctl swap` |
| `llarp.halt` | none | service stop (the service asks the router to exit) |

`list_exits` and `map_exit` also return `routes_up` (older builds leave it out; `rusty-ctl` then says the routes are unknown) and, when routes are down,
`routes_reason`.

`routes_up` is true as soon as an exit is mapped, whether or not the session to it is
live. So `rusty-ctl map` first maps the exit for `192.0.2.1/32` only (a documentation
address), which starts the session without touching the default route, polls
`list_exits` until that exit has `session_live` and `exit_capable`, and only then sends
the real `map_exit`. If it times out it calls `unmap_exit`. `rusty-ctl status` and
`exits` say "blocked" rather than "up" when routes are in but no mapped exit has a live
session.
