#pragma once
#include "types.hpp"

#include <optional>
#include <string_view>
#include <tuple>

namespace phosphor::network::netlink
{
/* Define constants for ifindex of interfaces */
#define IFINDEX_ETH0 2
#define IFINDEX_ETH1 3
#define IFINDEX_ETH2 4
#define IFINDEX_ETH3 5

InterfaceInfo intfFromRtm(std::string_view msg);

std::optional<std::tuple<unsigned, stdplus::InAnyAddr>> gatewayFromRtm(
    std::string_view msg);

AddressInfo addrFromRtm(std::string_view msg);

NeighborInfo neighFromRtm(std::string_view msg);

} // namespace phosphor::network::netlink
