# Rusty for Windows

Session Router with a small Rust service that helps keep your Windows network sane.
`rusty-ctl map` sends your traffic through a Session Router exit; `unmap` or
stopping the service puts everything back.

Not an official Session Foundation project.

Status: early test build, tested on Windows Server 2022 and Windows 11, including machines with several network adapters (Wi-Fi, Ethernet and other VPN adapters).

## What's here

| Path | What it is |
| --- | --- |
| `router/` | Session Router (C++), with Windows fixes. See [router/CHANGES.md](router/CHANGES.md). |
| `crates/rusty-service` | Runs the router as a Windows service, restarts it if it crashes, and restores routes, DNS and IPv6 whenever it stops. |
| `crates/rusty-net` | Routes and DNS through the IP Helper API, with a journal so a crash can be undone. |
| `crates/rusty-ctl` | Command line: status, exits, map, unmap, swap, and stop (stops the service). |
| `crates/rusty-rpc` | Client for the router's local RPC (OxenMQ over ZMTP). |
| `installer/` | `rusty-setup.exe`: one file that unpacks everything, makes a client key and installs the service. |

## Install

Run `rusty-setup.exe` (from a release, or the `rusty-setup` artifact of a CI run) and
accept the admin prompt. It installs to `C:\Rusty`, creates `client.key` on first run,
and prints this PC's `.sesh` address. Running a newer setup later updates the files and
keeps the key.

## Use

In an admin PowerShell:

```
cd C:\Rusty
sc.exe start RustySessionRouter
.\rusty-ctl.exe status
.\rusty-ctl.exe map <exit>.sesh --full      # everything through the exit
.\rusty-ctl.exe exits                       # wait for "session to exit: live"
.\rusty-ctl.exe unmap <exit>.sesh
.\rusty-ctl.exe stop                        # stops the service; network back as before
```

`--range 10.0.0.0/8` instead of `--full` sends only that range. If the exit only lets in
known clients, give its operator your address from `my-client-address.txt`; never share
`client.key`.

## Known issues

- Other VPNs (NordVPN and the like) fight over the default route. Disconnect them first.
  `rusty-ctl map` refuses while another adapter holds the default route or the
  0/1 + 128/1 pair, going by the live route table, not by whether a VPN app says it's
  connected. `rusty-ctl preflight` runs the same check and warns about leftover VPN
  routes and DNS. A kill switch done with firewall rules can't be seen without admin
  rights; the exit guard below covers that.
- The service unmaps an exit that doesn't come up within 90 s, one that stops answering
  for 30 s, and any exit while another VPN takes over the traffic. Your normal connection
  comes back on its own. `exit-guard.json` in `C:\Rusty` says what it last did.
- While an exit is mapped, IPv6 is off on all adapters except sr-tun0. It comes back on unmap, stop, or
  after a crash.
- If you map a full-tunnel exit and it isn't connected yet, websites won't load by name. Unmap it, or stop the service, and they work again.
- Windows only, x64 only.

## Build

CI ([.github/workflows/windows.yml](.github/workflows/windows.yml)) builds everything:
the router with MinGW on Debian, the Rust parts on Windows, and the installer.

- Rust parts: `cargo build --release` (Rust 1.85+). Tests run on Linux too:
  `cargo test`.
- Router: on Debian trixie with `mingw-w64` (posix threads),
  `router/contrib/windows-configure.sh router router/build/win32 -DSROUTER_GUI=OFF -DSUBMODULE_CHECK=OFF`
  then `make -C router/build/win32 session-router`.
- Installer: put the files listed in `installer/src/main.rs` in a folder, then
  `PACKAGE_DIR=/that/folder cargo build --release --target x86_64-pc-windows-gnu` in
  `installer/`.

## License

GPL-3.0-or-later, see [LICENSE](LICENSE). Third-party code under `router/external/` and
`router/cmake/session-deps` keeps its own licenses. `wintun.dll` is downloaded from
wintun.net at build time and ships with its own license.

## Run your own exit

Use the exit seller kit from [SeshSwap](https://github.com/carlcrainellc/seshswap) (`seller-kit/exit-seller.sh`, see `docs/EXITS.md` there). It sets up the exit, firewall and DNS in one command and prints the exit's `.sesh` address.

To let someone in without payment, add their client address:

```
sudo exit-seller.sh allow <their-address>.sesh
```

They find it in `my-client-address.txt` on Windows. `disallow` removes it and `allowed` lists them.

## Uninstall

In an admin PowerShell:

```
cd C:\Rusty
.\rusty-ctl.exe stop
.\rusty-service.exe uninstall
cd \
Remove-Item C:\Rusty -Recurse
```

`rusty-service.exe uninstall` removes both services, RustySessionRouter and
RustyNetRestore. If the folder is already gone, remove them with
`sc.exe delete RustySessionRouter` and `sc.exe delete RustyNetRestore`.

Deleting the folder alone leaves both services registered.
