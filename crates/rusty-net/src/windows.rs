//! IP Helper implementations of [`RouteTable`] and [`DnsSettings`].
//!
//! Routes go through `GetIpForwardTable2` / `CreateIpForwardEntry2` /
//! `DeleteIpForwardEntry2` instead of `route.exe`, so failures come back as error codes
//! rather than text on a console nobody reads. DNS uses `Get/SetInterfaceDnsSettings`
//! (Windows 10 2004 and later), the API behind the Settings app, instead of `netsh`.

use crate::{
    format_server_list, parse_server_list, ps_error, DnsSettings, Ipv4Net, Route, RouteTable,
};
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR, WIN32_ERROR,
};
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToGuid,
    ConvertInterfaceLuidToIndex, CreateIpForwardEntry2, DeleteIpForwardEntry2,
    FreeInterfaceDnsSettings, FreeMibTable, GetIfEntry2, GetInterfaceDnsSettings,
    GetIpForwardTable2, GetIpInterfaceEntry, InitializeIpForwardEntry, InitializeIpInterfaceEntry,
    SetInterfaceDnsSettings, DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1,
    DNS_SETTING_NAMESERVER, MIB_IF_ROW2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    MIB_IPINTERFACE_ROW,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{AF_INET, MIB_IPPROTO_NETMGMT};

fn check(e: WIN32_ERROR) -> io::Result<()> {
    if e == NO_ERROR {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(e.0 as i32))
    }
}

/// The system IPv4 route table.
#[derive(Debug, Default, Clone, Copy)]
pub struct IpHelperRoutes;

fn v4(addr: &windows::Win32::Networking::WinSock::SOCKADDR_INET) -> Option<Ipv4Addr> {
    unsafe {
        if addr.si_family != AF_INET {
            return None;
        }
        Some(Ipv4Addr::from(u32::from_be(addr.Ipv4.sin_addr.S_un.S_addr)))
    }
}

fn set_v4(addr: &mut windows::Win32::Networking::WinSock::SOCKADDR_INET, ip: Ipv4Addr) {
    addr.si_family = AF_INET;
    addr.Ipv4.sin_family = AF_INET;
    addr.Ipv4.sin_addr.S_un.S_addr = u32::from(ip).to_be();
}

fn row_for(r: &Route) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceIndex = r.if_index;
    set_v4(&mut row.DestinationPrefix.Prefix, r.dest.addr);
    row.DestinationPrefix.PrefixLength = r.dest.prefix;
    set_v4(&mut row.NextHop, r.next_hop);
    row.Metric = r.metric;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row
}

impl RouteTable for IpHelperRoutes {
    fn routes(&self) -> io::Result<Vec<Route>> {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        unsafe {
            check(GetIpForwardTable2(AF_INET, &mut table))?;
            let n = (*table).NumEntries as usize;
            let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
            let mut out = Vec::with_capacity(n);
            for row in rows {
                let (Some(dest), Some(hop)) = (v4(&row.DestinationPrefix.Prefix), v4(&row.NextHop))
                else {
                    continue;
                };
                if let Some(dest) = Ipv4Net::new(dest, row.DestinationPrefix.PrefixLength) {
                    out.push(Route {
                        dest,
                        next_hop: hop,
                        if_index: row.InterfaceIndex,
                        metric: row.Metric,
                    });
                }
            }
            FreeMibTable(table as *const _);
            Ok(out)
        }
    }

    fn add(&mut self, r: &Route) -> io::Result<()> {
        let row = row_for(r);
        match unsafe { CreateIpForwardEntry2(&row) } {
            e if e == ERROR_OBJECT_ALREADY_EXISTS => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("route {} already exists", r.dest),
            )),
            e => check(e),
        }
    }

    fn delete(&mut self, r: &Route) -> io::Result<()> {
        let row = row_for(r);
        match unsafe { DeleteIpForwardEntry2(&row) } {
            e if e == ERROR_NOT_FOUND => Ok(()),
            e => check(e),
        }
    }

    fn interface_metric(&self, if_index: u32) -> io::Result<u32> {
        let mut row = MIB_IPINTERFACE_ROW::default();
        unsafe {
            InitializeIpInterfaceEntry(&mut row);
            row.Family = AF_INET;
            row.InterfaceIndex = if_index;
            match GetIpInterfaceEntry(&mut row) {
                e if e == ERROR_NOT_FOUND => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no IPv4 interface {if_index}"),
                )),
                e => check(e).map(|_| row.Metric),
            }
        }
    }

    fn is_tunnel(&self, if_index: u32) -> bool {
        match if_row(if_index) {
            Some((if_type, description, alias)) => is_tunnel_like(
                if_type,
                &description.to_ascii_lowercase(),
                &alias.to_ascii_lowercase(),
            ),
            None => false,
        }
    }

    fn name_of(&self, if_index: u32) -> Option<String> {
        if_row(if_index).map(|(_, _, alias)| alias)
    }

    fn description_of(&self, if_index: u32) -> Option<String> {
        if_row(if_index).map(|(_, description, _)| description)
    }

    fn index_of(&self, name: &str) -> io::Result<Option<u32>> {
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let mut luid = NET_LUID_LH::default();
        let mut index = 0u32;
        unsafe {
            if ConvertInterfaceAliasToLuid(PCWSTR(wide.as_ptr()), &mut luid) != NO_ERROR {
                return Ok(None);
            }
            check(ConvertInterfaceLuidToIndex(&luid, &mut index))?;
        }
        Ok(Some(index))
    }
}

/// Type, description and alias of an interface.
fn if_row(if_index: u32) -> Option<(u32, String, String)> {
    let mut row = MIB_IF_ROW2 {
        InterfaceIndex: if_index,
        ..Default::default()
    };
    if unsafe { GetIfEntry2(&mut row) } != NO_ERROR {
        return None;
    }
    let text = |w: &[u16]| {
        let n = w.iter().position(|&c| c == 0).unwrap_or(w.len());
        String::from_utf16_lossy(&w[..n])
    };
    Some((row.Type, text(&row.Description), text(&row.Alias)))
}

/// IF_TYPE_PROP_VIRTUAL (Wintun, most VPN adapters) and IF_TYPE_TUNNEL, or anything that
/// says it is Wintun, a TAP or VPN adapter, or carries the router's interface name.
fn is_tunnel_like(if_type: u32, description: &str, alias: &str) -> bool {
    const IF_TYPE_PROP_VIRTUAL: u32 = 53;
    const IF_TYPE_TUNNEL: u32 = 131;
    if_type == IF_TYPE_PROP_VIRTUAL
        || if_type == IF_TYPE_TUNNEL
        || [
            "wintun",
            "wireguard",
            "tap-windows",
            "tap-",
            "vpn",
            " tunnel",
        ]
        .iter()
        .any(|w| description.contains(w))
        || alias.starts_with("sr-tun")
}

fn if_guid(if_index: u32) -> io::Result<GUID> {
    let mut luid = NET_LUID_LH::default();
    let mut guid = GUID::zeroed();
    unsafe {
        check(ConvertInterfaceIndexToLuid(if_index, &mut luid)).map_err(|_| {
            io::Error::new(io::ErrorKind::NotFound, format!("no interface {if_index}"))
        })?;
        check(ConvertInterfaceLuidToGuid(&luid, &mut guid))?;
    }
    Ok(guid)
}

/// Per-interface IPv4 DNS servers.
#[derive(Debug, Default, Clone, Copy)]
pub struct IpHelperDns;

impl DnsSettings for IpHelperDns {
    fn servers(&self, if_index: u32) -> io::Result<Vec<IpAddr>> {
        let guid = if_guid(if_index)?;
        let mut s = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            ..Default::default()
        };
        unsafe {
            check(GetInterfaceDnsSettings(guid, &mut s))?;
            let text = if s.NameServer.is_null() {
                String::new()
            } else {
                s.NameServer.to_string().unwrap_or_default()
            };
            FreeInterfaceDnsSettings(&mut s);
            Ok(parse_server_list(&text))
        }
    }

    fn set_servers(&mut self, if_index: u32, servers: &[IpAddr]) -> io::Result<()> {
        let guid = if_guid(if_index)?;
        // An empty NameServer string with the flag set hands the interface back to DHCP.
        let mut text: Vec<u16> = format_server_list(servers)
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let s = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            Flags: DNS_SETTING_NAMESERVER as u64,
            NameServer: PWSTR(text.as_mut_ptr()),
            ..Default::default()
        };
        unsafe { check(SetInterfaceDnsSettings(guid, &s)) }
    }
}

/// IPv6 bindings through the NetAdapter PowerShell module. There is no small Win32 call
/// for binding state (the alternative is the INetCfg COM interface), so this shells out,
/// but only to read state and to turn IPv6 back on, never off.
#[derive(Debug, Default, Clone, Copy)]
pub struct PsIpv6;

fn powershell(script: &str, adapter: Option<&str>) -> io::Result<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let sys = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    let exe = std::path::Path::new(&sys).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", script])
        .creation_flags(CREATE_NO_WINDOW);
    // The adapter name travels in an environment variable, never inside the script text.
    if let Some(a) = adapter {
        cmd.env("RUSTY_ADAPTER", a);
    }
    let out = cmd.output()?;
    if !out.status.success() {
        return Err(ps_error(
            out.status.code(),
            &String::from_utf8_lossy(&out.stderr),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

impl crate::Ipv6Bindings for PsIpv6 {
    fn enabled(&self) -> io::Result<Vec<String>> {
        let out = powershell(
            "Get-NetAdapterBinding -ComponentID ms_tcpip6 -IncludeHidden -ErrorAction SilentlyContinue | \
             Where-Object Enabled | ForEach-Object { $_.Name }",
            None,
        )?;
        Ok(out
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect())
    }

    fn enable(&mut self, adapter: &str) -> io::Result<()> {
        powershell(
            "$n = [Management.Automation.WildcardPattern]::Escape($env:RUSTY_ADAPTER); \
             if (-not (Get-NetAdapter -Name $n -IncludeHidden -ErrorAction SilentlyContinue)) { exit 3 }; \
             Enable-NetAdapterBinding -Name $n -ComponentID ms_tcpip6 -IncludeHidden -ErrorAction Stop",
            Some(adapter),
        )
        .map(|_| ())
    }
}
