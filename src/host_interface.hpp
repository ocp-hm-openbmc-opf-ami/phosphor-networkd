#pragma once
#include "types.hpp"
#include "xyz/openbmc_project/Network/IP/Create/server.hpp"

#include <nlohmann/json.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/sdbus.hpp>
#include <sdbusplus/server/interface.hpp>
#include <sdbusplus/server/object.hpp>
#include <sdbusplus/vtable.hpp>
#include <stdplus/pinned.hpp>
#include <stdplus/str/maps.hpp>
#include <stdplus/zstring_view.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Network/ARPControl/server.hpp>
#include <xyz/openbmc_project/Network/IP/server.hpp>
#include <xyz/openbmc_project/Network/MACAddress/server.hpp>

#include <memory>
#include <string>
#include <unordered_map>

namespace phosphor
{
namespace network
{
namespace hostintf
{

using hostIfaces = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Network::server::ARPControl,
    sdbusplus::xyz::openbmc_project::Network::server::MACAddress>;

using ARPControlIface =
    sdbusplus::xyz::openbmc_project::Network::server::ARPControl;

using MacAddressIntf =
    sdbusplus::xyz::openbmc_project::Network::server::MACAddress;

using IP = sdbusplus::xyz::openbmc_project::Network::server::IP;

using ObjectPath = sdbusplus::message::object_path;

class HostInterface;

using hostIPIfaces = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Network::server::IP>;

class HostIPAddress : public hostIPIfaces
{
  public:
    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objRoot - Path to attach at.
     *  @param[in] parent - Parent object.
     *  @param[in] addr - The ip address and prefix.
     *  @param[in] origin - origin of ipaddress(static/LinkLocal).
     */
    HostIPAddress(sdbusplus::bus_t& bus, std::string_view objRoot,
                  stdplus::PinnedRef<HostInterface> parent,
                  stdplus::SubnetAny addr, IP::AddressOrigin origin,
                  uint8_t idx);

    ~HostIPAddress() = default;

    std::string address(std::string ipAddress) override;
    uint8_t prefixLength(uint8_t) override;
    uint8_t idx(uint8_t) override;
    std::string gateway(std::string gateway) override;
    IP::Protocol type(IP::Protocol type) override;
    IP::AddressOrigin origin(IP::AddressOrigin origin) override;

    void delete_();

    using IP::address;
    using IP::gateway;
    using IP::idx;
    using IP::origin;
    using IP::prefixLength;
    using IP::type;

    inline const auto& getObjPath() const
    {
        return objPath;
    }

  private:
    /** @brief Parent Object. */
    stdplus::PinnedRef<HostInterface> parent;

    /** @brief Dbus object path */
    sdbusplus::message::object_path objPath;

    HostIPAddress(sdbusplus::bus_t& bus,
                  sdbusplus::message::object_path objPath,
                  stdplus::PinnedRef<HostInterface> parent,
                  stdplus::SubnetAny addr, IP::AddressOrigin origin,
                  uint8_t idx);
};

class HostInterface : public hostIfaces
{
  public:
    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objPath - Path to attach at.
     *  @param[in] info - Interface info.
     */
    HostInterface(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                  stdplus::zstring_view objPath, const InterfaceInfo& info);

    ~HostInterface() = default;

    void delete_();

    std::string macAddress(std::string value) override;

    std::unordered_map<stdplus::SubnetAny,
                       std::unique_ptr<hostintf::HostIPAddress>>
        addrs;

    void addAddr(const AddressInfo& info);

    void removeAddr(const AddressInfo& info);

    std::string InterfaceName() const
    {
        return std::string(intfName);
    }

    uint8_t getifindex() const
    {
        return ifindex;
    }

    bool arpResponse(bool value) override;

    bool gratuitousARP(bool value) override;

    uint64_t gratuitousARPInterval(uint64_t interval) override;

    using MacAddressIntf::macAddress;

  private:
    static constexpr const char HOST_INTERFACE_CONF_DIR[] = "/etc/interface";
    static constexpr const char* intfName = "hostusb0";
    static constexpr const char* ethIntf =
        "xyz.openbmc_project.Network.EthernetInterface";

    const bool dhcp4 = false;
    const std::string defaultGateway = "";
    const std::string backupGateway = "";
    const std::string backupGatewayMACAddress = "";
    const bool nicEnabled = true;

    const std::string defaultIpAddress = "169.254.0.17";
    const uint8_t defaultPrefixLength = 16;

    /** @brief Persistent sdbusplus DBus bus connection. */
    stdplus::PinnedRef<sdbusplus::bus_t> bus;

    /** @brief Path of Object. */
    std::string objPath;

    uint8_t ifindex;

    std::unique_ptr<sdbusplus::server::interface_t> ethernetInterface = nullptr;

    static const sdbusplus::vtable::vtable_t vtable[];

    int configureHostInterface(const std::string& ipaddress,
                               const uint8_t prefixLength,
                               const uint8_t ifindex);

    void createEthernetInterface();

    void writeConfigurationFile(stdplus::PinnedRef<HostIPAddress> addr);

    /**
     * Systemd bus callback for getting property
     */
    static int _callback_get_interface_name(
        sd_bus* bus, const char* path, const char* interface,
        const char* property, sd_bus_message* msg, void* context,
        sd_bus_error* error);

    static int _callback_get_dhcp4(sd_bus* bus, const char* path,
                                   const char* interface, const char* property,
                                   sd_bus_message* msg, void* context,
                                   sd_bus_error* error);

    static int _callback_get_default_gateway(
        sd_bus* bus, const char* path, const char* interface,
        const char* property, sd_bus_message* msg, void* context,
        sd_bus_error* error);

    static int _callback_get_backup_gateway(
        sd_bus* bus, const char* path, const char* interface,
        const char* property, sd_bus_message* msg, void* context,
        sd_bus_error* error);

    static int _callback_get_backup_gateway_mac_address(
        sd_bus* bus, const char* path, const char* interface,
        const char* property, sd_bus_message* msg, void* context,
        sd_bus_error* error);

    static int _callback_get_nic_enabled(
        sd_bus* bus, const char* path, const char* interface,
        const char* property, sd_bus_message* msg, void* context,
        sd_bus_error* error);
};

} // namespace hostintf

} // namespace network

} // namespace phosphor
