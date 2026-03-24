#pragma once
#if ENABLE_BOND_SUPPORT
#include "bond.hpp"
#endif
#include "config_parser.hpp"
#include "dhcp_configuration.hpp"
#include "ipaddress.hpp"
#include "ncsi_configuration.hpp"
#include "neighbor.hpp"
#include "router.hpp"
#include "types.hpp"
#include "util.hpp"
#include "xyz/openbmc_project/Channel/ChannelAccess/server.hpp"
#include "xyz/openbmc_project/Network/IP/Create/server.hpp"
#include "xyz/openbmc_project/Network/Neighbor/CreateStatic/server.hpp"

#include <nlohmann/json.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/server/object.hpp>
#include <stdplus/pinned.hpp>
#include <stdplus/str/maps.hpp>
#include <stdplus/zstring_view.hpp>
#include <xyz/openbmc_project/Collection/DeleteAll/server.hpp>
#include <xyz/openbmc_project/Network/ARPControl/server.hpp>
#if ENABLE_BOND_SUPPORT
#include <xyz/openbmc_project/Network/Bond/server.hpp>
#endif
#include <xyz/openbmc_project/Network/EthernetInterface/server.hpp>
#include <xyz/openbmc_project/Network/MACAddress/server.hpp>
#include <xyz/openbmc_project/Network/NCSIConfiguration/server.hpp>
#include <xyz/openbmc_project/Network/VLAN/server.hpp>
#include <xyz/openbmc_project/Object/Delete/server.hpp>

#include <optional>
#include <string>
#include <vector>

namespace phosphor
{
namespace network
{
using Ifaces = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Network::server::ARPControl,
    sdbusplus::xyz::openbmc_project::Network::server::EthernetInterface,
    sdbusplus::xyz::openbmc_project::Network::server::MACAddress,
    sdbusplus::xyz::openbmc_project::Network::IP::server::Create,
    sdbusplus::xyz::openbmc_project::Network::Neighbor::server::CreateStatic,
    sdbusplus::xyz::openbmc_project::Collection::server::DeleteAll,
    sdbusplus::xyz::openbmc_project::Channel::server::ChannelAccess>;

using ARPControlIface =
    sdbusplus::xyz::openbmc_project::Network::server::ARPControl;

using VlanIfaces = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Object::server::Delete,
    sdbusplus::xyz::openbmc_project::Network::server::VLAN>;

using VlanIntf = sdbusplus::xyz::openbmc_project::Network::server::VLAN;

using IP = sdbusplus::xyz::openbmc_project::Network::server::IP;

using EthernetInterfaceIntf =
    sdbusplus::xyz::openbmc_project::Network::server::EthernetInterface;
using MacAddressIntf =
    sdbusplus::xyz::openbmc_project::Network::server::MACAddress;
using ChannelAccessIntf =
    sdbusplus::xyz::openbmc_project::Channel::server::ChannelAccess;

using ServerList = std::vector<std::string>;
using ObjectPath = sdbusplus::message::object_path;

using DbusVariant = std::variant<std::string, std::vector<std::string>>;

using RACFG_T = std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, uint8_t,
                           std::vector<uint8_t>>;

class Manager;

class TestEthernetInterface;
class TestNetworkManager;

namespace config
{
class Parser;
}

#define MAX_SUPPORTED_DHCPv6_TIMING_PARAMS 12

namespace DHCPv6TimingParamDefault
{
constexpr uint8_t SOLMaxDelay = 2;
constexpr uint8_t SOLTimeout = 2;
constexpr uint8_t SOLMaxRt = 4;
constexpr uint8_t REQTimeout = 2;
constexpr uint8_t REQMaxRt = 211;
constexpr uint8_t REQMaxRc = 11;
constexpr uint8_t RENTimeout = 5;
constexpr uint8_t RENMaxRt = 60;
constexpr uint8_t REBTimeout = 5;
constexpr uint8_t REBMaxRt = 60;
constexpr uint8_t INFTimeout = 2;
constexpr uint8_t INFMaxRt = 4;
}; // namespace DHCPv6TimingParamDefault

enum class DHCPv6TimingParamIndex : uint8_t
{
    SOLMaxDelay = 0,
    SOLTimeout = 1,
    SOLMaxRt = 2,
    REQTimeout = 3,
    REQMaxRt = 4,
    REQMaxRc = 5,
    RENTimeout = 6,
    RENMaxRt = 7,
    REBTimeout = 8,
    REBMaxRt = 9,
    INFTimeout = 10,
    INFMaxRt = 11,
};

#define MAX_SUPPORTED_SLAAC_TIMING_PARAMS 11

namespace SLAACTimingParamIndex
{
constexpr int MaxRtrSolicitationDelay = 0;
constexpr int RtrSolicitationInterval = 1;
constexpr int MaxRtrSolicitations = 2;
constexpr int DupAddrDetectTransmits = 3;
constexpr int MaxMulticastSolicit = 4;
constexpr int MaxUnicastSolicit = 5;
constexpr int MaxAnycastDelayTime = 6;
constexpr int MaxNeighborAdvertisement = 7;
constexpr int ReachableTime = 8;
constexpr int RetransTimer = 9;
constexpr int DelayFirstProbeTime = 10;
}; // namespace SLAACTimingParamIndex

namespace SLAACTimingParamDefault
{
constexpr uint8_t MaxRtrSolicitationDelay = 4;
constexpr uint8_t RtrSolicitationInterval = 8;
constexpr uint8_t MaxRtrSolicitations = 255;
constexpr uint8_t DupAddrDetectTransmits = 2;
constexpr uint8_t MaxMulticastSolicit = 3;
constexpr uint8_t MaxUnicastSolicit = 3;
constexpr uint8_t MaxAnycastDelayTime = 4;
constexpr uint8_t MaxNeighborAdvertisement = 0;
constexpr uint8_t ReachableTime = 15;
constexpr uint8_t RetransTimer = 4;
constexpr uint8_t DelayFirstProbeTime = 10;
}; // namespace SLAACTimingParamDefault

/** @class EthernetInterface
 *  @brief OpenBMC Ethernet Interface implementation.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Network.EthernetInterface DBus API.
 */
class EthernetInterface : public Ifaces
{
  public:
    EthernetInterface(EthernetInterface&&) = delete;
    EthernetInterface& operator=(EthernetInterface&&) = delete;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] manager - parent object.
     *  @param[in] info - Interface information.
     *  @param[in] objRoot - Path to attach at.
     *  @param[in] config - The parsed configuation file.
     *  @param[in] vlan - The id of the vlan if configured
     *  @param[in] enabled - Determine if systemd-networkd is managing this link
     */
    EthernetInterface(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                      stdplus::PinnedRef<Manager> manager,
                      const AllIntfInfo& info, std::string_view objRoot,
                      const config::Parser& config, bool enabled);

    /** @brief Network Manager object. */
    stdplus::PinnedRef<Manager> manager;

    /** @brief Persistent map of IPAddress dbus objects and their names */
    std::unordered_map<stdplus::SubnetAny, std::unique_ptr<IPAddress>> addrs;

    /** @brief Persistent map of Neighbor dbus objects and their names */
    std::unordered_map<stdplus::InAnyAddr, std::unique_ptr<Neighbor>>
        staticNeighbors;
#if ENABLE_BOND_SUPPORT
    /** @brief Bonding dbus object */
    std::optional<Bond> bonding = std::nullopt;
#endif
    void addAddr(const AddressInfo& info);
    void addStaticNeigh(const NeighborInfo& info);

    /** @brief Updates the interface information based on new InterfaceInfo */
    void updateInfo(const InterfaceInfo& info, bool skipSignal = false);

    /** @brief Function used to load the ntpservers
     */
    void loadNTPServers(const config::Parser& config);

    /** @brief Function used to load the nameservers.
     */
    void loadNameServers(const config::Parser& config);

    /** @brief Function used to load the domainNames.
     */
    void loadDomainNames();

    /** @brief Get IPv6 Dynamic Router Address, Prefix, Prefix Length,
     * MACAddress
     */
    std::vector<RACFG_T> getIPv6DynamicRouterInfo() override;

    /** @brief load the ARP Control Configurations.
     */
    void loadARPControl();

    /** @brief Function to create ipAddress dbus object.
     *  @param[in] addressType - Type of ip address.
     *  @param[in] ipAddress- IP address.
     *  @param[in] prefixLength - Length of prefix.
     *  @param[in] ipgateway - Gateway address.
     */

    ObjectPath ip(IP::Protocol addressType, std::string ipAddress,
                  uint8_t prefixLength, std::string ipgateway) override;

    /** @brief Implementation for IPWithIndex
     *  Create ipaddress object with index.
     *
     *  @param[in] protocolType - protocol type can be IPv4 or IPv6 etc.
     *  @param[in] address - IP Address.
     *  @param[in] prefixLength - Prefix Length.
     *  @param[in] idx - Default index is 0. Index value for IPv4 is 0. Index
     * value for IPv6.
     *  @param[in] gateway - Gateway Address.
     *
     *  @return path[sdbusplus::message::object_path] - The path for the created
     * ipaddress object.
     */
    ObjectPath ipWithIndex(IP::Protocol protocolType, std::string address,
                           uint8_t prefixLength, uint8_t idx,
                           std::string gateway) override;

    /** @brief Function to create static neighbor dbus object.
     *  @param[in] ipAddress - IP address.
     *  @param[in] macAddress - Low level MAC address.
     */
    ObjectPath neighbor(std::string ipAddress, std::string macAddress,
                        uint8_t prefixLength) override;

    /** Set value of DomainName */
    std::vector<std::string> domainName(
        std::vector<std::string> value) override;

    /** Set value of DHCPEnabled */
    DHCPConf dhcpEnabled() const override;
    DHCPConf dhcpEnabled(DHCPConf value) override;
    using EthernetInterfaceIntf::dhcp4;
    bool dhcp4(bool value) override;
    using EthernetInterfaceIntf::dhcp6;
    bool dhcp6(bool value) override;

    inline bool dhcpIsEnabled(stdplus::In4Addr) const
    {
        return dhcp4();
    }
    inline bool dhcpIsEnabled(stdplus::In6Addr) const
    {
        return dhcp6();
    }
    inline bool dhcpIsEnabled(stdplus::InAnyAddr addr) const
    {
        return std::visit([&](auto v) { return dhcpIsEnabled(v); }, addr);
    }

    /** Get linkup status */
    bool linkUp() const override;

    /** Set size of MTU */
    size_t mtu(size_t value) override;

    /** Set value of NICEnabled */
    bool nicEnabled(bool value) override;

    /** @brief sets the MAC address.
     *  @param[in] value - MAC address which needs to be set on the system.
     *  @returns macAddress of the interface or throws an error.
     */
    std::string macAddress(std::string value) override;

    /** @brief check conf file for Router Advertisements
     *
     */
    bool ipv6AcceptRA(bool value) override;
    using EthernetInterfaceIntf::ipv6AcceptRA;

    /** @brief sets the NTP servers.
     *  @param[in] value - vector of NTP servers.
     */
    ServerList ntpServers(ServerList value) override;

    /** @brief sets the static NTP servers.
     *  @param[in] value - vector of NTP servers.
     */
    ServerList staticNTPServers(ServerList value) override;

    /** @brief Get value of nameservers */
    ServerList nameservers() const override;

    /** @brief sets the Static DNS/nameservers.
     *  @param[in] value - vector of DNS servers.
     */

    ServerList staticNameServers(ServerList value) override;

    /** @brief create Vlan interface.
     *  @param[in] id- VLAN identifier.
     */
    ObjectPath createVLAN(uint16_t id);
#if ENABLE_BOND_SUPPORT
    /** @brief create bond interface.
     *  @param[in] activeSlave- active slave.
     *  @param[in] miiMonitor- MII Monitor.
     */
    ObjectPath createBond(std::string activeSlave, uint8_t miiMonitor);
#endif
    /** @brief write the network conf file with the in-memory objects.
     */
    void writeConfigurationFile();

    /** @brief delete all dbus objects.
     */
    void deleteAll() override;

    /** @brief set the default v4 gateway of the interface.
     *  @param[in] gateway - default v4 gateway of the interface.
     */
    std::string defaultGateway(std::string gateway) override;

    /** @brief set the default v6 gateway of the interface.
     *  @param[in] gateway - default v6 gateway of the interface.
     */
    std::string defaultGateway6(std::string gateway) override;

    /** Get value of Speed */
    uint32_t speed() const override;

    /** Get value of Duplex */
    Duplex duplex() const override;

    void migrateIPIndex(std::string dst);

    /** @brief Implementation for SetPHYConfiguration
     *  Set the auto negotiation, duplex and speed in the current interface
     *
     *  @param[in] autoNeg -
     *  @param[in] duplex -
     *  @param[in] speed -
     *
     *  @return result[int16_t] -
     */
    int16_t setPHYConfiguration(bool autoNeg, Duplex duplex,
                                uint32_t speed) override;

    /** @brief Function to reload network configurations.
     */
    void reloadConfigs();

    /** @brief set the Enable/Disable of ARP Response in sysctl config.
     *  @param[in] value - Enable/Disable
     *  @return the status of ARP Response in sysctl config
     */
    bool arpResponse(bool value) override;

    /** @brief set the Enable/Disable of GratuitousARP.
     *  @param[in] value - Enable/Disable
     *  @return the status of GratuitousARP Broadcasting
     */
    bool gratuitousARP(bool value) override;

    /** @brief set the GratuitousARP interval.
     *  @param[in] interval - interval in milliseconds.
     */
    uint64_t gratuitousARPInterval(uint64_t interval) override;

    /** @brief set the Default Gateway MAC Addess.
     *  @param[in] gateway - Gateway4 address.
     */
    std::tuple<std::optional<std::string>, uint8_t> getDwMacAddrByIP(
        std::string gateway);

    /** Set value of LinkLocalAutoConf */
    LinkLocalConf linkLocalAutoConf(LinkLocalConf value) override;

    /** Set value of IPv6Enable */
    bool ipv6Enable(bool value) override;

    /** Set value of IPv4Enable */
    bool ipv4Enable(bool value) override;

    /** Set value of IPv6EnableStaticRtr */
    bool ipv6EnableStaticRtr(bool value) override;

    /** Set value of IPv6StaticRtrAddr */
    std::string ipv6StaticRtrAddr(std::string value) override;

    /** Set value of IPv6StaticRtr2Addr */
    std::string ipv6StaticRtr2Addr(std::string value) override;

    /** Delete the index according to given IP address*/
    void delIpIdx(std::string address, IP::Protocol protocolType);

    /** List to save index and IPv4 Address */
    std::vector<std::optional<std::string>> ipv4IndexUsedList;

    /** List to save index and IPv6 Address */
    std::vector<std::optional<std::string>> ipv6IndexUsedList;

    /** Previous DHCP6 state to restore when re-enabling IPv6 */
    bool preDhcp6State = false;

    /** Previous DHCP4 state to restore when re-enabling IPv4 */
    bool preDhcp4State = false;

    std::optional<dhcp::Configuration> dhcp4Conf, dhcp6Conf;

    /** @brief Get current interface index.
     */
    uint8_t getIfIdx();

    /** Get value of DHCPv6DUID */
    std::string dhcpv6DUID() const override;

    /** Set value of DHCPv6TimingConfParam */
    std::vector<uint8_t> dhcpv6TimingConfParam(
        std::vector<uint8_t> value) override;

    /** Parse dhcpv6 timing param to write to network config file */
    void dhcpv6TimingParamWriteConfFile(config::Parser& config);

    /** Read dhcpv6 timing param from iface config file */
    std::vector<uint8_t> dhcpv6TimingParamReadIfaceFile(
        const config::Parser& config);

    /** Set value of IPv6SLAACTimingConfParam */
    std::vector<uint8_t> ipv6SLAACTimingConfParam(
        std::vector<uint8_t> value) override;

    /** Read slaac timing param from iface config file */
    std::vector<uint8_t> slaacTimingParamReadIfaceFile(
        const config::Parser& config);

    /** @brief sets the channel maxium privilege.
     *  @param[in] value - Channel privilege which needs to be set on the
     * system.
     *  @returns privilege of the interface or throws an error.
     */
    std::string maxPrivilege(std::string value) override;

    using ChannelAccessIntf::maxPrivilege;

    /** Set value of BackupGateway */
    std::string backupGateway(std::string value) override;

    /** Get value of BackupGatewayMACAddress */
    std::string backupGatewayMACAddress() const override;

    /** Get Metric value of Default Gateway */
    uint16_t getMetricValueDefaultGateway(std::string value);

#if ENABLE_BOND_SUPPORT
    void updateBondConfBackupForSlaveMAC(std::string, std::string);
#endif

    using EthernetInterfaceIntf::interfaceName;
    using EthernetInterfaceIntf::linkUp;
    using EthernetInterfaceIntf::mtu;
    using EthernetInterfaceIntf::nicEnabled;
    using MacAddressIntf::macAddress;

    using ARPControlIface::arpResponse;
    using ARPControlIface::gratuitousARP;
    using ARPControlIface::gratuitousARPInterval;
    using EthernetInterfaceIntf::autoNeg;
    using EthernetInterfaceIntf::backupGateway;
    using EthernetInterfaceIntf::defaultGateway;
    using EthernetInterfaceIntf::defaultGateway6;
    using EthernetInterfaceIntf::dhcpv6DUID;
    using EthernetInterfaceIntf::dhcpv6TimingConfParam;
    using EthernetInterfaceIntf::domainName;
    using EthernetInterfaceIntf::ipv4Enable;
    using EthernetInterfaceIntf::ipv6Enable;
    using EthernetInterfaceIntf::ipv6EnableStaticRtr;
    using EthernetInterfaceIntf::ipv6SLAACTimingConfParam;
    using EthernetInterfaceIntf::ipv6StaticRtr2Addr;
    using EthernetInterfaceIntf::ipv6StaticRtrAddr;
    using EthernetInterfaceIntf::linkLocalAutoConf;
    using EthernetInterfaceIntf::nameservers;
    using EthernetInterfaceIntf::staticNameServers;

  protected:
    /** @brief get the NTP server list from the timsyncd dbus obj
     *
     */
    virtual ServerList getNTPServerFromTimeSyncd();

    /** @brief get the name server details from the network conf
     *
     */
    virtual ServerList getNameServerFromResolvd() const;

    /** @brief Persistent sdbusplus DBus bus connection. */
    stdplus::PinnedRef<sdbusplus::bus_t> bus;

    /** @brief Dbus object path */
    std::string objPath;

    /** @brief Interface index */
    unsigned ifIdx;

    struct VlanProperties : VlanIfaces
    {
        VlanProperties(sdbusplus::bus_t& bus, stdplus::const_zstring objPath,
                       const InterfaceInfo& info,
                       stdplus::PinnedRef<EthernetInterface> eth);
        void delete_() override;
        unsigned parentIdx;
        stdplus::PinnedRef<EthernetInterface> eth;
    };
    std::optional<VlanProperties> vlan;

    /** @brief NCSI dbus object */
    std::optional<ncsi::Configuration> ncsiConfig = std::nullopt;

    /** @brief get the domain names details from the network conf
     *
     */
    virtual ServerList getDomainNamesFromResolvd();

    std::map<std::string, std::unique_ptr<sdbusplus::bus::match_t>>
        initSignals();

    void registerSignal(sdbusplus::bus::bus& bus);

    friend class TestEthernetInterface;
    friend class TestNetworkManager;

  private:
    struct SavedIPAddr
    {
        std::string address;
        uint8_t prefixLength;
        std::string gateway;
    };
    std::vector<SavedIPAddr> savedStaticIPv6Addrs;
    std::vector<SavedIPAddr> savedStaticIPv4Addrs;
    std::unique_ptr<std::thread> vlanMonitorThread;

    std::mutex vlanMutex;

    std::atomic<bool> vlanMonitorActive{true};

    void startVlanMonitorThread();

    void monitorVlanInterface();

    void reregisterSignals();

    EthernetInterface(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                      stdplus::PinnedRef<Manager> manager,
                      const AllIntfInfo& info, std::string&& objPath,
                      const config::Parser& config, bool enabled);

    /** @brief Determines if the address is manually assigned
     *  @param[in] origin - The origin entry of the IP::Address
     *  @returns true/false value if the address is static
     */
    bool originIsManuallyAssigned(IP::AddressOrigin origin,
                                  IP::Protocol family);

    /** @brief write the ARP Control configuration into the conf file.
     */
    void writeConfiguration();

    void writeIfaceStateFile(std::string ifname);

    void writeNicConfiguration(bool isActive);

    /** @brief set the ARP Response status in sysctl config for the ethernet
     * interface.
     *  @param[in] cmd - shell command.
     *  @return status of the shell command execution
     */
    bool sysctlConfig(const std::string& cmd);

    /** @brief Get the number of created VLAN interface
     *  @param[in] confFile - The path of NetIntf configuration
     *  @return status of the shell command execution
     */
    int getCreatedVLANNum(std::filesystem::__cxx11::path confFile);

    /** @brief Return the minimun index or the existing index by given address
     *  @param[in] list - The list of IP address
     *  @param[in] addr - The new IP address need giving index
     *  @return Index of IP address in the list
     */
    template <
        sdbusplus::common::xyz::openbmc_project::network::IP::Protocol family>
    int getProperIpIdx(std::vector<std::optional<std::string>>& list,
                       stdplus::InAnyAddr addr);

    /** @brief Update index table by the given address
     *  @param[in] addr - The new IP address need adding into table
     *  @param[in] index - The index of IP address
     */
    void updateIpIndex(stdplus::SubnetAny addr, std::variant<bool, int> index);

    /** @brief Function to create ipAddress dbus object.
     *  @param[in] protType - Type of ip address.
     *  @param[in] ipAddress- IP address.
     *  @param[in] prefixLength - Length of prefix.
     *  @param[in] ipgateway - Gateway address.
     *  @return A tuple containing whether the IP address exists and the object
     * path
     */
    std::tuple<bool, ObjectPath> createStaticIP(
        IP::Protocol protType, std::string ipaddress, uint8_t prefixLength,
        std::string ipgateway);

    std::map<std::string, std::unique_ptr<sdbusplus::bus::match_t>> signals;

    /** @brief gets the channel privilege.
     *  @param[in] interfaceName - Network interface name.
     *  @returns privilege of the interface
     */
    std::string getChannelPrivilege(const std::string& interfaceName);

    /** @brief reads the channel access info from file.
     *  @param[in] configFile - channel access filename
     *  @returns json file data
     */
    nlohmann::json readJsonFile(const std::string& configFile);

    /** @brief writes the channel access info to file.
     *  @param[in] configFile - channel access filename
     *  @param[in] jsonData - json data to write
     *  @returns success or failure
     */
    int writeJsonFile(const std::string& configFile,
                      const nlohmann::json& jsonData);
};

} // namespace network
} // namespace phosphor
