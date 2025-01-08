#pragma once

#include "ncsi_util.hpp"
#include "types.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <stdplus/pinned.hpp>
#include <stdplus/zstring.hpp>
#include <xyz/openbmc_project/Network/NCSIConfiguration/server.hpp>
#include <xyz/openbmc_project/Object/Delete/server.hpp>

#include <string_view>

namespace phosphor
{
namespace network
{
class EthernetInterface; // forward declaration of EthernetInterface

using NCSIIface =
    sdbusplus::xyz::openbmc_project::Network::server::NCSIConfiguration;

using NCSIObj = sdbusplus::server::object_t<NCSIIface>;
namespace ncsi
{

constexpr int MAX_PACKAGE_NUM = 7;
constexpr int MAX_CHANNEL_NUM = 31;

class Configuration : NCSIObj
{
  public:
    Configuration() = delete;
    Configuration(const Configuration&) = delete;
    Configuration& operator=(const Configuration&) = delete;
    Configuration(Configuration&&) = delete;
    Configuration& operator=(Configuration&&) = delete;
    virtual ~Configuration() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     *  @param[in] eth - Ethernet Interface to attach at.
     *  @param[in] mode - NCSI mode
     *  @param[in] package - Package
     *  @param[in] channel - Channel
     */
    // Configuration(sdbusplus::bus_t& bus, std::string_view path,
    // EthernetInterface& eth);
    Configuration(sdbusplus::bus_t& bus, std::string_view path,
                  EthernetInterface& eth, NCSIIface::Mode mode, uint8_t package,
                  uint8_t channel);
    /** Set value of Mode */
    Mode mode(Mode value) override;

    /** @brief Implementation for SetPackageChannel
     *  Set preferred package and channel
     *
     *  @param[in] package - Preferred package
     *  @param[in] channel - Preferred channel
     *
     *  @return result[int16_t] -
     */
    int16_t setPackageChannel(uint8_t package, uint8_t channel) override;

    /** Get value of ChannelList */
    std::vector<std::tuple<uint16_t, std::vector<uint16_t>>>
        channelList() const override;

    using NCSIIface::channel;
    using NCSIIface::mode;
    using NCSIIface::package;

  private:
    /** @brief sdbusplus DBus bus connection. */
    sdbusplus::bus_t& bus;

    /** @brief Parent Object. */
    EthernetInterface& eth;
};

} // namespace ncsi
} // namespace network
} // namespace phosphor
