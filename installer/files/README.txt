Rusty for Windows (early test build)
===================================

Session Router plus a Windows service (Rusty) that runs it and puts your
network settings back when it stops or crashes. "rusty-ctl map" sends your
traffic through a Session Router exit.

Use it (admin PowerShell)
-------------------------
   cd C:\Rusty
   sc.exe start RustySessionRouter
   .\rusty-ctl.exe status
   .\rusty-ctl.exe map <exit>.sesh --full
   .\rusty-ctl.exe exits        (wait for "session to exit: live")
   .\rusty-ctl.exe unmap <exit>.sesh
   .\rusty-ctl.exe stop         (stops the service)

If the exit only lets in known clients, give its operator this PC's address
from my-client-address.txt. Never share client.key.

Update: run the new setup. It stops the service, replaces the program
files and keeps client.key.

Things to know
--------------
- Turn off other VPNs first. rusty-ctl warns if one has a default route.
- With an exit mapped, IPv6 is turned off on all adapters; it comes back on
  unmap, stop, or after a crash.
- If you map a full-tunnel exit and it isn't connected yet, websites won't
  load by name. Unmap it, or stop the service, and they work again.
- ".\rusty-ctl.exe stop" (or "sc.exe stop RustySessionRouter") stops the
  service and puts your old DNS servers and routes back.
- Logs: rusty-service.log and session-router.log in C:\Rusty.

Licenses: GPL-3.0-or-later (see LICENSE); wintun.dll is from wintun.net,
see wintun-LICENSE.txt. Source: the repository this release came from.

Uninstall (admin PowerShell)
----------------------------
   cd C:\Rusty
   .\rusty-ctl.exe stop
   .\rusty-service.exe uninstall      (removes both services)
   cd \
   Remove-Item C:\Rusty -Recurse

If the folder is already gone: sc.exe delete RustySessionRouter and
sc.exe delete RustyNetRestore. Deleting the folder alone leaves both
services registered.
