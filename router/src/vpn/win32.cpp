#include "win32.hpp"

#include "win32/adapters.hpp"
#include "win32/windivert.hpp"
#include "win32/wintun.hpp"

#include <fmt/core.h>

#include <algorithm>
#include <netioapi.h>

namespace srouter::win32
{

    void VPNPlatform::make_route(std::string ip, std::string gw, std::string cmd)
    {
        srouter::win32::Exec(
            "route.exe", fmt::format("{} {} MASK 255.255.255.255 {} METRIC {}", cmd, ip, gw, m_Metric));
    }

    void VPNPlatform::default_route_via_interface(NetworkInterface& vpn, std::string cmd)
    {
        // No 127.0.0.0/8 "hole": Windows already has 127.0.0.0/8 on the loopback interface,
        // which is more specific than the two /1 halves. Adding one landed it on the physical
        // adapter, and "route DELETE 127.0.0.0 MASK 255.0.0.0" then removed the system's own
        // loopback routes too.
        // set up ipv4 routes
        route_via_interface(vpn, "0.0.0.0", "128.0.0.0", cmd);
        route_via_interface(vpn, "128.0.0.0", "128.0.0.0", cmd);
    }

    void VPNPlatform::route_via_interface(NetworkInterface& vpn, std::string addr, std::string mask, std::string cmd)
    {
        const auto& info = vpn.interface_info();
        if (info.addrs.empty())
            throw std::runtime_error{"win32 route_via_interface: interface has no addresses"};
        auto ifaddr = std::visit([](const auto& a) { return a.ip.to_string(); }, info.addrs[0]);
        // this changes the last 1 to a 0 so that it routes over the interface
        // this is required because windows is idiotic af
        ifaddr.back()--;
        srouter::win32::Exec("route.exe", fmt::format("{} {} MASK {} {} METRIC {}", cmd, addr, mask, ifaddr, m_Metric));
    }

    namespace
    {
        std::string ipv4_netmask_dotted(uint8_t mask)
        {
            if (mask == 0)
                return "0.0.0.0";
            uint32_t m = (mask >= 32) ? 0xFFFFFFFFu : (0xFFFFFFFFu << (32 - mask));
            return fmt::format("{}.{}.{}.{}", (m >> 24) & 0xff, (m >> 16) & 0xff, (m >> 8) & 0xff, m & 0xff);
        }
    }  // namespace

    void VPNPlatform::add_route(ipv4 ip, ipv4 gateway)
    {
        make_route(ip.to_string(), gateway.to_string(), "ADD");
    }

    void VPNPlatform::add_route(ipv6 ip, ipv6 gateway)
    {
        srouter::win32::Exec(
            "route.exe",
            fmt::format("-6 ADD {}/128 {} METRIC {}", ip.to_string(), gateway.to_string(), m_Metric));
    }

    void VPNPlatform::delete_route(ipv4 ip, ipv4 gateway)
    {
        make_route(ip.to_string(), gateway.to_string(), "DELETE");
    }

    void VPNPlatform::delete_route(ipv6 ip, ipv6 gateway)
    {
        srouter::win32::Exec(
            "route.exe",
            fmt::format("-6 DELETE {}/128 {}", ip.to_string(), gateway.to_string()));
    }

    void VPNPlatform::add_route_via_interface(NetworkInterface& vpn, ipv4_range range)
    {
        route_via_interface(vpn, range.ip.to_string(), ipv4_netmask_dotted(range.mask), "ADD");
    }

    void VPNPlatform::add_route_via_interface(NetworkInterface& vpn, ipv6_range range)
    {
        const auto& info = vpn.interface_info();
        srouter::win32::Exec(
            "netsh.exe",
            fmt::format(
                "interface ipv6 add route {}/{} \"{}\"",
                range.ip.to_string(),
                range.mask,
                info.ifname));
    }

    void VPNPlatform::delete_route_via_interface(NetworkInterface& vpn, ipv4_range range)
    {
        route_via_interface(vpn, range.ip.to_string(), ipv4_netmask_dotted(range.mask), "DELETE");
    }

    void VPNPlatform::delete_route_via_interface(NetworkInterface& vpn, ipv6_range range)
    {
        const auto& info = vpn.interface_info();
        srouter::win32::Exec(
            "netsh.exe",
            fmt::format(
                "interface ipv6 delete route {}/{} \"{}\"",
                range.ip.to_string(),
                range.mask,
                info.ifname));
    }

    std::vector<quic::Address> VPNPlatform::get_non_interface_gateways(NetworkInterface& vpn)
    {
        // Gateways of the default routes that traffic really uses, best first: only adapters
        // that are up, never our own TUN, ordered by route metric + interface metric (what
        // Windows itself compares). The old code returned every adapter's gateway sorted by
        // address, so a second adapter (another VPN, a stale TAP) with a lower-numbered
        // gateway got the first-hop pins and relay traffic fell into the TUN.
        const auto tun_index = vpn.interface_info().index;
        struct Candidate
        {
            ULONG metric;
            quic::Address gw;
        };
        std::vector<Candidate> found;

        PMIB_IPFORWARD_TABLE2 table = nullptr;
        if (GetIpForwardTable2(AF_UNSPEC, &table) != NO_ERROR or not table)
            return {};
        for (ULONG i = 0; i < table->NumEntries; ++i)
        {
            const auto& r = table->Table[i];
            if (r.DestinationPrefix.PrefixLength != 0 or r.InterfaceIndex == tun_index)
                continue;
            const auto fam = r.NextHop.si_family;
            quic::Address gw;
            if (fam == AF_INET)
            {
                if (r.NextHop.Ipv4.sin_addr.s_addr == 0)
                    continue;
                gw = quic::Address{reinterpret_cast<const sockaddr*>(&r.NextHop.Ipv4), sizeof(sockaddr_in)};
            }
            else if (fam == AF_INET6)
            {
                if (IN6_IS_ADDR_UNSPECIFIED(&r.NextHop.Ipv6.sin6_addr))
                    continue;
                gw = quic::Address{reinterpret_cast<const sockaddr*>(&r.NextHop.Ipv6), sizeof(sockaddr_in6)};
            }
            else
                continue;

            MIB_IF_ROW2 ifrow{};
            ifrow.InterfaceIndex = r.InterfaceIndex;
            if (GetIfEntry2(&ifrow) != NO_ERROR or ifrow.OperStatus != IfOperStatusUp)
                continue;

            MIB_IPINTERFACE_ROW iprow;
            InitializeIpInterfaceEntry(&iprow);
            iprow.Family = fam;
            iprow.InterfaceIndex = r.InterfaceIndex;
            const ULONG if_metric = GetIpInterfaceEntry(&iprow) == NO_ERROR ? iprow.Metric : 0;

            found.push_back({r.Metric + if_metric, std::move(gw)});
        }
        FreeMibTable(table);

        std::stable_sort(found.begin(), found.end(), [](const auto& a, const auto& b) { return a.metric < b.metric; });
        std::vector<quic::Address> gateways;
        for (auto& c : found)
            gateways.push_back(std::move(c.gw));
        return gateways;
    }

    namespace
    {
        // PowerShell single-quoted literal: ' doubles.
        std::string ps_quote(const std::string& v)
        {
            std::string out{"'"};
            for (char c : v)
            {
                if (c == '\'')
                    out += "''";
                else if (c != '"')
                    out += c;
            }
            return out + "'";
        }
    }  // namespace

    void VPNPlatform::set_ipv6_on_other_adapters(NetworkInterface& vpn, bool on)
    {
        const auto& ifname = vpn.interface_info().ifname;
        srouter::win32::Exec(
            "WindowsPowerShell\\v1.0\\powershell.exe",
            fmt::format(
                "-NoProfile -NonInteractive -Command \"Get-NetAdapterBinding -ComponentID ms_tcpip6 "
                "-IncludeHidden -ErrorAction SilentlyContinue | Where-Object {{ $_.Name -ne {} }} | "
                "{}-NetAdapterBinding -ErrorAction SilentlyContinue\"",
                ps_quote(ifname),
                on ? "Enable" : "Disable"));
    }

    void VPNPlatform::ensure_tun_ipv6(NetworkInterface& vpn)
    {
        const auto& info = vpn.interface_info();
        for (const auto& a : info.addrs)
        {
            const auto* n6 = std::get_if<ipv6_net>(&a);
            if (not n6)
                continue;
            // Idempotent: "already exists" when the address is still there. Adding it with its
            // prefix also puts back the on-link fd2e::/N route.
            srouter::win32::Exec(
                "netsh.exe",
                fmt::format(
                    "interface ipv6 add address interface=\"{}\" address={}/{} store=active",
                    info.ifname,
                    n6->ip.to_string(),
                    n6->mask));
        }
    }

    void VPNPlatform::add_default_route_via_interface(NetworkInterface& vpn)
    {
        // Stop IPv6 leaking past the tunnel: turn it off on every adapter EXCEPT our own TUN.
        // .sesh names resolve to AAAA in our fd2e:: range only, so the TUN must keep IPv6 (and
        // its address + on-link route). Toggling ms_tcpip6 on the TUN wipes that address, and
        // re-enabling the binding does not bring it back: every .sesh dial then fails with "no
        // route" until the router restarts.
        set_ipv6_on_other_adapters(vpn, false);
        ensure_tun_ipv6(vpn);

        default_route_via_interface(vpn, "ADD");
    }

    void VPNPlatform::delete_default_route_via_interface(NetworkInterface& vpn)
    {
        set_ipv6_on_other_adapters(vpn, true);
        // Belt and braces for TUNs whose IPv6 was stripped by an older build (or anything else).
        ensure_tun_ipv6(vpn);

        default_route_via_interface(vpn, "DELETE");
    }

    std::shared_ptr<NetworkInterface> VPNPlatform::obtain_interface(InterfaceInfo info, Router* router)
    {
        return wintun::make_interface(std::move(info), router);
    }

    std::shared_ptr<PacketIO> VPNPlatform::create_packet_io(
        unsigned int ifindex, const std::optional<quic::Address>& dns_upstream_src)
    {
        // we only want do this on all interfaes with windivert
        if (ifindex)
            throw std::invalid_argument{
                "cannot create packet io on explicitly specified interface, not currently "
                "supported on "
                "windows (yet)"};

        uint16_t upstream_src_port = dns_upstream_src ? dns_upstream_src->port() : 0;
        std::string udp_filter = upstream_src_port != 0
            ? fmt::format("( udp.DstPort == 53 and udp.SrcPort != {} )", upstream_src_port)
            : "udp.DstPort == 53";

        auto filter = "outbound and ( " + udp_filter + " or tcp.DstPort == 53 )";

        return WinDivert::make_interceptor(filter, [router = _ctx->router] { /* router->TriggerPump(); */ });
    }
}  // namespace srouter::win32
