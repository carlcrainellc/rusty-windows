#pragma once

#include "address/address.hpp"
#include "address/ip_range.hpp"
#include "net/ip_packet.hpp"
#include "net/traffic_type.hpp"

#include <optional>
#include <string>
#include <utility>

namespace srouter::handlers
{
    // Core-side interface for the TUN endpoint.  Router holds and drives an ITunnel; the concrete
    // implementation (TunEndpoint, which needs the platform/vpn layer) lives in the full library and
    // is constructed via the full-only seam.  In embedded/core-only builds Router never constructs one
    // (the pointer stays null), so core references only this interface -- never the platform code.
    struct ITunnel
    {
        virtual ~ITunnel() = default;

        virtual void start_poller() = 0;
        virtual void stop() = 0;

        virtual std::string get_if_name() const = 0;

        virtual const ipv4_net& get_ipv4_network() const = 0;
        virtual const ipv6_net& get_ipv6_network() const = 0;

        virtual void handle_inbound_packet(IPPacket pkt, traffic_type type, NetworkAddress remote) = 0;

        virtual ipv6 map6(const NetworkAddress& remote) = 0;
        virtual std::optional<ipv4> map4(const NetworkAddress& remote) = 0;

        virtual void expire(const NetworkAddress& remote) = 0;

        virtual std::pair<std::optional<NetworkAddress>, bool> reverse_lookup(const ipv4& ip) = 0;
        virtual std::pair<std::optional<NetworkAddress>, bool> reverse_lookup(const ipv6& ip) = 0;

        // Exit client: install / remove OS default route via this TUN (route poker).
        // No-op default so embedded/core builds stay free of vpn types.
        virtual void add_default_route() {}
        virtual void delete_default_route() {}

        // Exit mappings changed at runtime (MapExit / UnmapExit / SwapExits RPC): bring the
        // route poker up when the first mapping appears and down when the last one goes.
        virtual void exit_mappings_changed() {}

        // Whether traffic for mapped exits is routed into the TUN right now, and if not, why.
        virtual std::pair<bool, std::string_view> exit_route_status() const { return {false, "no vpn interface"}; }

        // True when this router is operating as a clear exit (config [exit] enable=true).
        virtual bool is_exit_node() const { return false; }
    };

}  // namespace srouter::handlers
