#include "config.h"

#include "ethernet_interface.hpp"

#include "network_manager.hpp"
#include "system_queries.hpp"
#include "util.hpp"

#include <arpa/inet.h>
#include <linux/if_packet.h> /* struct sockaddr_ll (see man 7 packet) */
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <sys/ioctl.h> /* macro ioctl is defined */
#include <sys/stat.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <stdplus/fd/create.hpp>
#include <stdplus/raw.hpp>
#include <stdplus/str/cat.hpp>
#include <stdplus/zstring.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <algorithm>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <variant>

namespace phosphor
{
namespace network
{

using namespace std::string_literals;
using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using NotAllowed = sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;
using NotAllowedArgument = xyz::openbmc_project::Common::NotAllowed;
using Argument = xyz::openbmc_project::Common::InvalidArgument;
using Unsupported = xyz::openbmc_project::Common::UnsupportedRequest;
using std::literals::string_view_literals::operator""sv;
constexpr auto RESOLVED_SERVICE = "org.freedesktop.resolve1";
constexpr auto RESOLVD_OBJ_PATH = "/org/freedesktop/resolve1";
constexpr auto RESOLVED_INTERFACE = "org.freedesktop.resolve1.Link";
constexpr auto RESOLVD_MANAGER_INTERFACE = "org.freedesktop.resolve1.Manager";
constexpr auto DHCP_PROP_INTERFACE =
    "xyz.openbmc_project.Network.DHCPConfiguration";
constexpr auto DHCP_SERVICE_PATH = "/xyz/openbmc_project/network/dhcp";
constexpr auto PROPERTY_INTERFACE = "org.freedesktop.DBus.Properties";
constexpr auto RESOLVED_SERVICE_PATH = "/org/freedesktop/resolve1/link/";
constexpr auto NETWORKD_LINK_PATH_PREFIX = "/org/freedesktop/network1/link/";
constexpr auto NETWORKD_SERVICE = "org.freedesktop.network1";
constexpr auto NETWORKD_LINK_INTERFACE = "org.freedesktop.network1.Link";

constexpr auto TIMESYNCD_SERVICE = "org.freedesktop.timesync1";
constexpr auto TIMESYNCD_INTERFACE = "org.freedesktop.timesync1.Manager";
constexpr auto TIMESYNCD_SERVICE_PATH = "/org/freedesktop/timesync1";

constexpr auto METHOD_GET = "Get";

static constexpr const char* networkChannelCfgFile =
    "/var/channel_intf_data.json";
static constexpr const char* defaultChannelPriv = "priv-admin";

constexpr auto garpControlService = "xyz.openbmc_project.GARPControl.service";
constexpr auto sysctlConfigPrefix = "/proc/sys/net/ipv4/conf/";
constexpr auto sysctlConfigSurffix = "/arp_ignore";
std::string arpResponseDisable = "echo 8 >";
std::string arpResponseEnable = "echo 0 >";

constexpr auto VLAN_MAX_NUM = 2;

const float SLAAC_Timing_Param[2 * MAX_SUPPORTED_SLAAC_TIMING_PARAMS] = {
    /*Granularity        InitialValue*/
    0.25, 0.25, 0.5,  0.5, 1, 1, 1, 0,    1,    1,   1,
    1,    0.25, 0.25, 1,   1, 2, 2, 0.25, 0.25, 0.5, 0.5,
};

const float DHCPv6_Timing_Param[2 * MAX_SUPPORTED_DHCPv6_TIMING_PARAMS] = {
    /*Granularity       InitialValue*/
    0.5, 0.5, 0.5, 0.5, 30, 30, 0.5, 0.5, 0.5, 15,  1,  0,
    2,   2,   10,  10,  2,  2,  10,  10,  0.5, 0.5, 30, 30,
};
#if ENABLE_BOND_SUPPORT
const std::string bondIfcName = "bond0";
#endif
template <typename Func>
inline decltype(std::declval<Func>()()) ignoreError(
    std::string_view msg, stdplus::zstring_view intf,
    decltype(std::declval<Func>()()) fallback, Func&& func) noexcept
{
    try
    {
        return func();
    }
    catch (const std::exception& e)
    {
        lg2::error("{MSG} failed on {NET_INTF}: {ERROR}", "MSG", msg,
                   "NET_INTF", intf, "ERROR", e);
    }
    return fallback;
}

static std::string makeObjPath(std::string_view root, std::string_view intf)
{
    auto ret = stdplus::strCat(root, "/"sv, intf);
    std::replace(ret.begin() + ret.size() - intf.size(), ret.end(), '.', '_');
    return ret;
}

template <typename Addr>
static bool validIntfIP(Addr a) noexcept
{
    return a.isUnicast() && !a.isLoopback();
}

EthernetInterface::EthernetInterface(
    stdplus::PinnedRef<sdbusplus::bus_t> bus,
    stdplus::PinnedRef<Manager> manager, const AllIntfInfo& info,
    std::string_view objRoot, const config::Parser& config, bool enabled) :
    EthernetInterface(bus, manager, info, makeObjPath(objRoot, *info.intf.name),
                      config, enabled)
{}

EthernetInterface::EthernetInterface(
    stdplus::PinnedRef<sdbusplus::bus_t> bus,
    stdplus::PinnedRef<Manager> manager, const AllIntfInfo& info,
    std::string&& objPath, const config::Parser& config, bool enabled) :
    Ifaces(bus, objPath.c_str(), Ifaces::action::defer_emit), manager(manager),
    bus(bus), objPath(std::move(objPath))
{
    interfaceName(*info.intf.name, true);
    auto dhcpVal = getDHCPValue(config);
    #if ENABLE_BOND_SUPPORT
    auto bondNetdevBackup = config::pathForIntfDev(manager.get().getConfDir(), bondIfcName);
    #endif
    EthernetInterfaceIntf::dhcp4(dhcpVal.v4, true);
    EthernetInterfaceIntf::dhcp6(dhcpVal.v6, true);
    EthernetInterfaceIntf::ipv6AcceptRA(getIPv6AcceptRA(config), true);
    EthernetInterfaceIntf::nicEnabled(enabled, true);

    EthernetInterfaceIntf::ntpServers(
        config.map.getValueStrings("Network", "NTP"), true);

    updateInfo(info.intf, true);

    const config::Parser& ifaceConfig(fs::path{
        fmt::format("{}/{}", manager.get().ifaceConfDir.generic_string(),
                    interfaceName())
            .c_str()});

    if (!EthernetInterfaceIntf::dhcp4())
    {
        EthernetInterfaceIntf::backupGateway(getIPv4BackupGateway(ifaceConfig));
        EthernetInterfaceIntf::defaultGateway(
            getIPv4DefaultGateway(ifaceConfig));
    }
    else
    {
        if (info.defgw4)
        {
            EthernetInterfaceIntf::defaultGateway(stdplus::toStr(*info.defgw4),
                                                  true);
        }
    }

    if (info.defgw6)
    {
        EthernetInterfaceIntf::defaultGateway6(stdplus::toStr(*info.defgw6),
                                               true);
    }

    EthernetInterfaceIntf::ipv4Enable(getIP4Enable(ifaceConfig), true);
    EthernetInterfaceIntf::ipv6Enable(getIP6Enable(ifaceConfig), true);
    EthernetInterfaceIntf::ipv6EnableStaticRtr(getIP6StaticRtr(ifaceConfig),
                                               true);
    if (EthernetInterfaceIntf::ipv6EnableStaticRtr())
    {
        EthernetInterfaceIntf::ipv6StaticRtrAddr(
            getIP6StaticRtrAddr(ifaceConfig, "Router1"), true);
        EthernetInterfaceIntf::ipv6StaticRtr2Addr(
            getIP6StaticRtrAddr(ifaceConfig, "Router2"), true);
    }
    EthernetInterfaceIntf::dhcpv6TimingConfParam(
        dhcpv6TimingParamReadIfaceFile(ifaceConfig), true);

    ipv6SLAACTimingConfParam(slaacTimingParamReadIfaceFile(ifaceConfig));

    auto [ipv4List, ipv6List] = getIndexList(ifaceConfig);
    if (!EthernetInterfaceIntf::dhcp4())
    {
        ipv4IndexUsedList = std::move(ipv4List);
    }

    if (!EthernetInterfaceIntf::dhcp6())
    {
        ipv6IndexUsedList = std::move(ipv6List);
    }

    ipv4IndexUsedList.resize(IPV4_MAX_NUM + 1, std::nullopt);
    ipv6IndexUsedList.resize(IPV6_MAX_NUM + 1, std::nullopt);

    EthernetInterfaceIntf::ncsi(false, true);

#if AMI_NCSI_SUPPORT
    if (std::string{DEFAULT_NCSI_INTERFACE}.find(interfaceName()) !=
        std::string::npos)
    {
        auto [mode, package, channel] = getNCSIValue(ifaceConfig);
        ncsiConfig.emplace(
            bus, this->objPath.c_str(), *this,
            mode == "Manual" ? NCSIIface::Mode::Manual : NCSIIface::Mode::Auto,
            mode == "Manual" ? package : ncsi::MAX_PACKAGE_NUM,
            mode == "Manual" ? channel : ncsi::MAX_CHANNEL_NUM);
        EthernetInterfaceIntf::ncsi(true, true);
    }
#endif

    if (!ncsi())
    {
        try
        {
            if (auto phyConf = getPHYInfo(ifaceConfig); phyConf.has_value())
            {
#if ENABLE_BOND_SUPPORT
                if (!this->vlan.has_value() && !this->bonding.has_value())
#else
                if (!this->vlan.has_value())
#endif
                {
                    auto [autoNeg, duplex, speed] = phyConf.value();
                    if (!autoNeg && !duplex.empty() || speed > 0)
                    {
                        EthernetInterfaceIntf::autoNeg(autoNeg, true);
                        EthernetInterfaceIntf::duplex(
                            duplex == "full" ? Duplex::full : Duplex::half,
                            true);
                        EthernetInterfaceIntf::speed(speed, true);
                        system::setLink(interfaceName(), speed,
                                        duplex == "full" ? 1 : 0,
                                        autoNeg ? 1 : 0);
                    }
                }
            }
        }
        catch (const std::exception& e)
        {
            log<level::ERR>(fmt::format("e.what() = {}", e.what()).c_str());
        }
    }

    this->loadARPControl();
    emit_object_added();

    if (info.intf.vlan_id)
    {
        if (!info.intf.parent_idx)
        {
            std::runtime_error("Missing parent link");
        }
        vlan.emplace(bus, this->objPath.c_str(), info.intf, *this);
        if (ifIdx == 0)
        { // VLAN interface not ready yet
            startVlanMonitorThread();
        }
    }
    dhcp4Conf.emplace(bus, this->objPath + "/dhcp4", *this, DHCPType::v4);
    dhcp6Conf.emplace(bus, this->objPath + "/dhcp6", *this, DHCPType::v6);
#if ENABLE_BOND_SUPPORT
    if (info.intf.bondInfo)
    {
        auto miiMonitorVal = info.intf.bondInfo->miiMonitor;
        if (fs::exists(bondNetdevBackup))
        {
            config::Parser parser(bondNetdevBackup);
            auto value = parser.map.getLastValueString("Bond", "MIIMonitorSec");
            if (value) miiMonitorVal = static_cast<uint8_t>(std::stoi(*value));
        }
        if (!info.intf.parent_idx)
        {
            std::runtime_error("Missing parent link");
        }
        bonding.emplace(
            bus, this->objPath.c_str(), *this, info.intf.bondInfo->activeSlave,
            miiMonitorVal, Bond::Mode::ActiveBackup);
    }
#endif
    for (const auto& [_, addr] : info.addrs)
    {
        addAddr(addr);
    }
    for (const auto& [_, neigh] : info.staticNeighs)
    {
        addStaticNeigh(neigh);
    }
#if ENABLE_BOND_SUPPORT
    if (std::string mac = getMAC(config); (!mac.empty() && !info.intf.bondInfo))
#else
    if (std::string mac = getMAC(config); !mac.empty())
#endif
    {
        system::setNICUp(interfaceName(), false);
        MacAddressIntf::macAddress(mac, true);
        manager.get().reconfigLink(ifIdx);
    }

    signals = initSignals();
    registerSignal(bus);
#if NSUPDATE_SUPPORT
    manager.get().getDNSConf().addInterfaceConf(interfaceName());
#endif
}

void EthernetInterface::startVlanMonitorThread()
{
    std::lock_guard<std::mutex> lock(vlanMutex);
    if (!vlanMonitorThread)
    {
        vlanMonitorThread =
            std::make_unique<std::thread>([this]() { monitorVlanInterface(); });
    }
}

void EthernetInterface::monitorVlanInterface()
{
    while (vlanMonitorActive.load())
    {
        if (unsigned int newIdx = if_nametoindex(interfaceName().c_str()))
        {
            std::lock_guard<std::mutex> lock(vlanMutex);
            if (vlanMonitorActive.load())
            { // Check flag under lock
                ifIdx = newIdx;
                reregisterSignals();
            }
            return;
        }
    }
}

void EthernetInterface::reregisterSignals()
{
    for (auto& [name, match] : signals)
    {
        match.reset(nullptr);
    }
    registerSignal(bus);
}

void EthernetInterface::updateInfo(const InterfaceInfo& info, bool skipSignal)
{
    ifIdx = info.idx;
    EthernetInterfaceIntf::linkUp(info.flags & IFF_RUNNING, skipSignal);
#ifdef AMI_NCSI_SUPPORT
    if (std::string{DEFAULT_NCSI_INTERFACE}.find(interfaceName()) !=
        std::string::npos)
    {
#ifdef AMI_NCSI_MANUAL_DETECTION
        EthernetInterfaceIntf::linkUp(false, skipSignal);
#else
        auto v = phosphor::network::ncsi::getLinkStatus(ifIdx);
        EthernetInterfaceIntf::linkUp(
            phosphor::network::ncsi::getLinkStatus(ifIdx), skipSignal);
#endif
    }
#endif
    config::Parser config(
        config::pathForIntfConf(manager.get().getConfDir(), interfaceName()));
    if (std::string mac = getMAC(config);
        !mac.empty() && MacAddressIntf::macAddress() != mac)
    {
        system::setNICUp(interfaceName(), false);
        MacAddressIntf::macAddress(mac, true);
        manager.get().reconfigLink(ifIdx);
    }
    else if (info.mac)
    {
        if (stdplus::toStr(*info.mac) != MacAddressIntf::macAddress() &&
            manager.get().initCompleted)
        {
            MacAddressIntf::macAddress(stdplus::toStr(*info.mac), skipSignal);
            manager.get().reconfigLink(ifIdx);
        }
        else
            MacAddressIntf::macAddress(stdplus::toStr(*info.mac), skipSignal);
    }
    if (info.mtu)
    {
        EthernetInterfaceIntf::mtu(*info.mtu, skipSignal);
    }
#if ENABLE_BOND_SUPPORT
    if (info.bondInfo)
    {
        auto it = manager.get().interfaces.find(bondIfcName);
        if (it != manager.get().interfaces.end())
        {
            it->second->bonding->activeSlave(info.bondInfo->activeSlave,
                                             skipSignal);
        }
    }
#endif
    if (ifIdx > 0)
    {
        auto ethInfo = ignoreError("GetEthInfo", *info.name, {}, [&] {
            return system::getEthInfo(*info.name);
        });
        EthernetInterfaceIntf::autoNeg(ethInfo.autoneg, skipSignal);
        EthernetInterfaceIntf::speed(ethInfo.speed, skipSignal);
        EthernetInterfaceIntf::duplex(
            ethInfo.duplex == 1 ? Duplex::full : Duplex::half, skipSignal);
    }

    getChannelPrivilege(*info.name);
}

bool EthernetInterface::originIsManuallyAssigned(IP::AddressOrigin origin,
                                                 IP::Protocol family)
{
    bool status = false;

    if (family == IP::Protocol::IPv4)
    {
        status =
#ifdef IPV4_LINK_LOCAL
            (origin == IP::AddressOrigin::Static)
#endif
#ifdef IPV6_LINK_LOCAL
                (origin == IP::AddressOrigin::Static ||
                 origin == IP::AddressOrigin::LinkLocal)
#endif

#ifdef IPV4_IPV6_LINK_LOCAL
                    (origin == IP::AddressOrigin::Static)
#endif
#ifdef DISABLE_LINK_LOCAL
                        (origin == IP::AddressOrigin::Static ||
                         origin == IP::AddressOrigin::LinkLocal)
#endif
            ;
    }
    else
    {
        status =
#ifdef IPV4_LINK_LOCAL
            (origin == IP::AddressOrigin::Static ||
             origin == IP::AddressOrigin::LinkLocal)
#endif
#ifdef IPV6_LINK_LOCAL
                (origin == IP::AddressOrigin::Static)
#endif
#ifdef IPV4_IPV6_LINK_LOCAL
                    (origin == IP::AddressOrigin::Static)
#endif
#ifdef DISABLE_LINK_LOCAL
                        (origin == IP::AddressOrigin::Static ||
                         origin == IP::AddressOrigin::LinkLocal)
#endif
            ;
    }
    return status;
}

void EthernetInterface::addAddr(const AddressInfo& info)
{
    IP::AddressOrigin origin = IP::AddressOrigin::Static;
    if (dhcpIsEnabled(info.ifaddr.getAddr()))
    {
        origin = IP::AddressOrigin::DHCP;
    }

#if defined(IPV4_LINK_LOCAL) || defined(IPV6_LINK_LOCAL) ||                    \
    defined(IPV4_IPV6_LINK_LOCAL)
    if (info.scope == RT_SCOPE_LINK)
    {
        origin = IP::AddressOrigin::LinkLocal;
    }
#endif

    if ((info.scope == RT_SCOPE_UNIVERSE) && (info.flags & IFA_F_PERMANENT))
    {
        origin = IP::AddressOrigin::Static;
    }
    if ((info.scope == RT_SCOPE_UNIVERSE) &&
        ((info.flags & IFA_F_NOPREFIXROUTE) &&
         (info.flags & IFA_F_MANAGETEMPADDR)))
    {
        origin = IP::AddressOrigin::SLAAC;
    }
    else if ((info.scope == RT_SCOPE_UNIVERSE) &&
             ((info.flags & IFA_F_NOPREFIXROUTE)))
    {
        origin = IP::AddressOrigin::DHCP;
    }

    auto it = addrs.find(info.ifaddr);
    if (it == addrs.end())
    {
        int idx = 0;
        if (origin == IP::AddressOrigin::Static)
        {
            auto tmpAddr = stdplus::toStr(info.ifaddr.getAddr());
            if (tmpAddr.find(":") != std::string::npos)
            {
                idx = getProperIpIdx<IP::Protocol::IPv6>(ipv6IndexUsedList,
                                                         info.ifaddr.getAddr());
            } // if
            else if (tmpAddr.find(".") != std::string::npos)
            {
                idx = getProperIpIdx<IP::Protocol::IPv4>(ipv4IndexUsedList,
                                                         info.ifaddr.getAddr());
            }
        }
        addrs.emplace(info.ifaddr, std::make_unique<IPAddress>(
                                       bus, std::string_view(objPath), *this,
                                       info.ifaddr, origin, idx));
    }
    else
    {
        it->second->IPIfaces::origin(origin);
    }
}

void EthernetInterface::addStaticNeigh(const NeighborInfo& info)
{
    if (!info.mac || !info.addr)
    {
        lg2::error("Missing neighbor mac on {NET_INTF}", "NET_INTF",
                   interfaceName());
        return;
    }

    uint8_t prefixLength = info.prefixLength;
    const config::Parser& ifaceConfig(fs::path{
        fmt::format("{}/{}", manager.get().ifaceConfDir.generic_string(),
                    interfaceName())
            .c_str()});
    if (EthernetInterfaceIntf::ipv6EnableStaticRtr())
    {
        if (!EthernetInterfaceIntf::ipv6StaticRtrAddr().empty() &&
            EthernetInterfaceIntf::ipv6StaticRtrAddr() ==
                stdplus::toStr(*info.addr))
        {
            prefixLength = getIP6StaticRtrPrefix(ifaceConfig, "Router1");
        }
        if (!EthernetInterfaceIntf::ipv6StaticRtr2Addr().empty() &&
            EthernetInterfaceIntf::ipv6StaticRtr2Addr() ==
                stdplus::toStr(*info.addr))
        {
            prefixLength = getIP6StaticRtrPrefix(ifaceConfig, "Router2");
        }
    }

    if (auto it = staticNeighbors.find(*info.addr); it != staticNeighbors.end())
    {
        it->second->NeighborObj::macAddress(stdplus::toStr(*info.mac));
        it->second->NeighborObj::prefixLength(prefixLength);
    }
    else
    {
        staticNeighbors.emplace(
            *info.addr,
            std::make_unique<Neighbor>(bus, std::string_view(objPath), *this,
                                       *info.addr, *info.mac, prefixLength,
                                       Neighbor::State::Permanent));
    }
}

void EthernetInterface::updateIpIndex(stdplus::SubnetAny addr,
                                      std::variant<bool, int> index)
{
    int idx = 0;

    try
    {
        if (std::get_if<bool>(&index))
        {
            std::string ipaddress = stdplus::toStr(addr);
            if (ipaddress.find(":") != std::string::npos)
            {
                idx = getProperIpIdx<IP::Protocol::IPv6>(ipv6IndexUsedList,
                                                         addr.getAddr());
            } // if
            else if (ipaddress.find(".") != std::string::npos)
            {
                idx = getProperIpIdx<IP::Protocol::IPv4>(ipv4IndexUsedList,
                                                         addr.getAddr());
            }
        } // if
        else
        {
            idx = *std::get_if<int>(&index);
        } // else

        std::string ipaddress = stdplus::toStr(addr.getAddr());
        if (ipaddress.find(":") != std::string::npos)
        {
            for (const auto& v : ipv6IndexUsedList)
            {
                if (v == ipaddress)
                {
                    goto EXIT;
                } // if
            }

            if (ipv6IndexUsedList.size() <= idx)
            {
                ipv6IndexUsedList.resize(idx + 1, std::nullopt);
            }
            ipv6IndexUsedList.at(idx) = std::move(ipaddress);
        } // if
        else if (ipaddress.find(".") != std::string::npos)
        {
            for (const auto& v : ipv4IndexUsedList)
            {
                if (v == ipaddress)
                {
                    goto EXIT;
                } // if
            }

            if (ipv4IndexUsedList.size() <= idx)
            {
                ipv4IndexUsedList.resize(idx + 1, std::nullopt);
            }
            ipv4IndexUsedList.at(idx) = std::move(ipaddress);
        }
    }
    catch (const std::exception& e)
    {
        log<level::INFO>(
            fmt::format("Couldn't update index: {}\n", e.what()).c_str());
    }

    try
    {
        auto it = addrs.find(addr);
        if (it != addrs.end())
        {
            it->second->IP::idx(idx);
        }
        else
        {
            throw std::logic_error("No matched IP address found");
        }
    }
    catch (const std::exception& e)
    {
        log<level::INFO>(
            fmt::format("Couldn't update index: {}\n", e.what()).c_str());
    }

EXIT:
    return;
}

std::tuple<bool, ObjectPath> EthernetInterface::createStaticIP(
    IP::Protocol protType, std::string ipaddress, uint8_t prefixLength,
    std::string ipgateway)
{
    std::optional<stdplus::InAnyAddr> addr, gateway;
    try
    {
        switch (protType)
        {
            case IP::Protocol::IPv4:
                if (!EthernetInterface::ipv4Enable() ||
                    EthernetInterface::dhcp4())
                {
                    throw NotAllowed();
                }
                addr.emplace(stdplus::fromStr<stdplus::In4Addr>(ipaddress));
                ip_address::isValidIPv4Addr((in_addr*)(&addr.value()),
                                            ip_address::Type::IP4_ADDRESS);
                if (!ipgateway.empty())
                {
                    ip_address::isSameSeries(ipaddress, ipgateway,
                                             prefixLength);
                    gateway.emplace(
                        stdplus::fromStr<stdplus::In4Addr>(ipgateway));
                    ip_address::isValidIPv4Addr(
                        (in_addr*)(&gateway.value()),
                        ip_address::Type::GATEWAY4_ADDRESS);
                    EthernetInterfaceIntf::defaultGateway(ipgateway);
                }
                break;
            case IP::Protocol::IPv6:
                if (!EthernetInterface::ipv6Enable() ||
                    EthernetInterface::dhcp6())
                {
                    throw NotAllowed();
                }
                if (!ipgateway.empty())
                {
                    for (auto& addr6 : addrs)
                    {
                        if (addr6.second->type() != IP::Protocol::IPv6 ||
                            addr6.second->origin() != IP::AddressOrigin::Static)
                        {
                            continue;
                        }
                        if (ipgateway.compare(addr6.second->address()) == 0)
                        {
                            log<level::ERR>(
                                "IP Address and Gateway are the same\n");
                            elog<NotAllowed>(NotAllowedArgument::REASON(
                                "IP Address and Gateway are the same\n"));
                        }
                    }

                    if (ipgateway.compare(ipaddress) == 0)
                    {
                        log<level::ERR>(
                            "IP Address and Gateway are the same\n");
                        elog<NotAllowed>(NotAllowedArgument::REASON(
                            "IP Address and Gateway are the same\n"));
                    }
                }
                else if (auto gw6 = EthernetInterfaceIntf::defaultGateway6();
                         !gw6.empty() &&
                         gw6.find("fe80::") == std::string::npos)
                {
                    if (gw6.compare(ipaddress) == 0)
                    {
                        log<level::ERR>(
                            "IP Address and Gateway are the same\n");
                        elog<NotAllowed>(NotAllowedArgument::REASON(
                            "IP Address and Gateway are the same\n"));
                    }
                }
                addr.emplace(stdplus::fromStr<stdplus::In6Addr>(ipaddress));
                ip_address::isValidIPv6Addr((in6_addr*)(&addr.value()),
                                            ip_address::Type::IP6_ADDRESS);
                if (!ipgateway.empty())
                {
                    gateway.emplace(
                        stdplus::fromStr<stdplus::In6Addr>(ipgateway));
                    ip_address::isValidIPv6Addr((in6_addr*)(&gateway.value()),
                                                ip_address::Type::IP6_ADDRESS);
                    EthernetInterfaceIntf::defaultGateway6(ipgateway);
                }
                break;
            default:
                throw std::logic_error("Exhausted protocols");
        }
        if (!std::visit([](auto ip) { return validIntfIP(ip); }, *addr))
        {
            throw std::invalid_argument("not unicast");
        }
    }
    catch (const NotAllowed& e)
    {
        log<level::ERR>(
            fmt::format("Not support in current state. {}\n", e.what())
                .c_str());
        elog<NotAllowed>(NotAllowedArgument::REASON(e.what()));
    }
    catch (const std::exception& e)
    {
        lg2::error("Invalid IP {NET_IP}: {ERROR}", "NET_IP", ipaddress, "ERROR",
                   e);
        lg2::error("Invalid IP {IP_GATEWAY}: {ERROR}", "IP_GATEWAY", ipgateway,
                   "ERROR", e);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("ipaddress"),
                              Argument::ARGUMENT_VALUE(ipaddress.c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("ipgateway"),
                              Argument::ARGUMENT_VALUE(ipgateway.c_str()));
    }
    std::optional<stdplus::SubnetAny> ifaddr;
    try
    {
        if (prefixLength == 0)
        {
            throw std::invalid_argument("default route");
        }
        ifaddr.emplace(*addr, prefixLength);
    }
    catch (const std::exception& e)
    {
        lg2::error("Invalid prefix length {NET_PFX}: {ERROR}", "NET_PFX",
                   prefixLength, "ERROR", e);
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("prefixLength"),
            Argument::ARGUMENT_VALUE(stdplus::toStr(prefixLength).c_str()));
    }

    auto it = addrs.find(*ifaddr);
    if (it == addrs.end())
    {
        it = std::get<0>(
            addrs.emplace(*ifaddr, std::make_unique<IPAddress>(
                                       bus, std::string_view(objPath), *this,
                                       *ifaddr, IP::AddressOrigin::Static, 0)));
    }
    else
    {
        if (it->second->origin() == IP::AddressOrigin::Static)
        {
            return std::make_tuple(false, it->second->getObjPath());
        }
        it->second->IPIfaces::origin(IP::AddressOrigin::Static);
    }

    return std::make_tuple(true, it->second->getObjPath());
}

ObjectPath EthernetInterface::ip(IP::Protocol protType, std::string ipaddress,
                                 uint8_t prefixLength, std::string ipgateway)
{
    std::optional<stdplus::InAnyAddr> addr;
    try
    {
        int count = 0;
        if (protType == IP::Protocol::IPv6)
        {
            std::for_each(ipv6IndexUsedList.begin(), ipv6IndexUsedList.end(),
                          [&](const std::optional<std::string> v) {
                              if (v.has_value())
                              {
                                  count += 1;
                              }
                          });
            if (count >= IPV6_MAX_NUM)
            {
                auto msg = fmt::format(
                    "The number of IPv6 address id out of limit {}. ",
                    IPV6_MAX_NUM);
                throw std::logic_error(msg.c_str());
            }

            addr.emplace(stdplus::fromStr<stdplus::In6Addr>(ipaddress));
        } // if
        else if (protType == IP::Protocol::IPv4)
        {
            std::for_each(ipv4IndexUsedList.begin(), ipv4IndexUsedList.end(),
                          [&](const std::optional<std::string> v) {
                              if (v.has_value())
                              {
                                  count += 1;
                              }
                          });
            if (count >= IPV4_MAX_NUM)
            {
                auto msg = fmt::format(
                    "The number of IPv4 address id out of limit {}. ",
                    IPV4_MAX_NUM);
                throw std::logic_error(msg.c_str());
            } // if

            addr.emplace(stdplus::fromStr<stdplus::In4Addr>(ipaddress));
        } // else if
    }
    catch (const std::exception& e)
    {
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("ipaddress"),
                              Argument::ARGUMENT_VALUE(ipaddress.c_str()));
    }

    auto [reload,
          path] = createStaticIP(protType, ipaddress, prefixLength, ipgateway);
    std::optional<stdplus::SubnetAny> ifaddr;
    try
    {
        if (prefixLength == 0)
        {
            throw std::invalid_argument("default route");
        }
        ifaddr.emplace(*addr, prefixLength);
    }
    catch (const std::exception& e)
    {
        lg2::error("Invalid prefix length {NET_PFX}: {ERROR}", "NET_PFX",
                   prefixLength, "ERROR", e);
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("prefixLength"),
            Argument::ARGUMENT_VALUE(stdplus::toStr(prefixLength).c_str()));
    }

    if (reload)
    {
        updateIpIndex(*ifaddr, false);
        writeConfigurationFile();
        manager.get().reloadConfigs();
    } // if

    return path;
}

ObjectPath EthernetInterface::ipWithIndex(
    IP::Protocol protType, std::string ipaddress, uint8_t prefixLength,
    uint8_t idx, std::string ipgateway)
{
    int count = 0;
    std::optional<stdplus::InAnyAddr> addr;
    try
    {
        if (protType == IP::Protocol::IPv6)
        {
            std::for_each(ipv6IndexUsedList.begin(), ipv6IndexUsedList.end(),
                          [&](const std::optional<std::string> v) {
                              if (v.has_value())
                              {
                                  count += 1;
                              }
                          });
            if (idx >= IPV6_MAX_NUM || count >= IPV6_MAX_NUM)
            {
                auto errMsg = fmt::format("IPv6 Index {} is out of limit {}. ",
                                          idx, IPV6_MAX_NUM);
                throw std::logic_error(errMsg);
            } // if
            else if (ipv6IndexUsedList.size() > idx &&
                     ipv6IndexUsedList.at(idx).has_value())
            {
                throw std::logic_error(
                    fmt::format("IPv6 The Index #{} is already used\n", idx)
                        .c_str());
            }

            addr.emplace(stdplus::fromStr<stdplus::In6Addr>(ipaddress));
        } // if
        else if (protType == IP::Protocol::IPv4)
        {
            std::for_each(ipv4IndexUsedList.begin(), ipv4IndexUsedList.end(),
                          [&](const std::optional<std::string> v) {
                              if (v.has_value())
                              {
                                  count += 1;
                              }
                          });
            if (idx >= IPV4_MAX_NUM || count >= IPV4_MAX_NUM)
            {
                auto errMsg = fmt::format("IPv4 Index {} is out of limit {}. ",
                                          idx, IPV4_MAX_NUM);
                throw std::logic_error(errMsg);
            } // if
            else if (ipv4IndexUsedList.size() > idx &&
                     ipv4IndexUsedList.at(idx).has_value())
            {
                throw std::logic_error(
                    fmt::format("IPv4 The Index #{} is already used.\n", idx)
                        .c_str());
            }

            addr.emplace(stdplus::fromStr<stdplus::In4Addr>(ipaddress));
        } // else if
    }
    catch (const std::exception& e)
    {
        log<level::INFO>(fmt::format("{}\n", e.what()).c_str());
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("idx"),
            Argument::ARGUMENT_VALUE(stdplus::toStr(idx).c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("ipaddress"),
                              Argument::ARGUMENT_VALUE(ipaddress.c_str()));
    }

    auto [reload,
          path] = createStaticIP(protType, ipaddress, prefixLength, ipgateway);
    std::optional<stdplus::SubnetAny> ifaddr;
    try
    {
        if (prefixLength == 0)
        {
            throw std::invalid_argument("default route");
        }
        ifaddr.emplace(*addr, prefixLength);
    }
    catch (const std::exception& e)
    {
        lg2::error("Invalid prefix length {NET_PFX}: {ERROR}", "NET_PFX",
                   prefixLength, "ERROR", e);
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("prefixLength"),
            Argument::ARGUMENT_VALUE(stdplus::toStr(prefixLength).c_str()));
    }

    if (reload)
    {
        updateIpIndex(*ifaddr, idx);
        writeConfigurationFile();
        manager.get().reloadConfigs();
    } // if

    return path;
}

void EthernetInterface::delIpIdx(std::string address, IP::Protocol protocolType)
{
    if (protocolType == IP::Protocol::IPv4)
    {
        for (int i = 0; i < IPV4_MAX_NUM; i++)
        {
            if (ipv4IndexUsedList.at(i).value_or("0.0.0.0") == address)
            {
                ipv4IndexUsedList.at(i) = std::nullopt;
                break;
            } // if
        } // for
    } // if
    else if (protocolType == IP::Protocol::IPv6)
    {
        for (int i = 0; i < IPV6_MAX_NUM; i++)
        {
            if (ipv6IndexUsedList.at(i).value_or("::") == address)
            {
                ipv6IndexUsedList.at(i) = std::nullopt;
                break;
            } // if
        } // for
    }
}

ObjectPath EthernetInterface::neighbor(
    std::string ipAddress, std::string macAddress, uint8_t prefixLength)
{
    std::optional<stdplus::InAnyAddr> addr;
    try
    {
        addr.emplace(stdplus::fromStr<stdplus::InAnyAddr>(ipAddress));
    }
    catch (const std::exception& e)
    {
        lg2::error("Not a valid IP address {NET_IP}: {ERROR}", "NET_IP",
                   ipAddress, "ERROR", e);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("ipAddress"),
                              Argument::ARGUMENT_VALUE(ipAddress.c_str()));
    }

    std::optional<stdplus::EtherAddr> lladdr;
    try
    {
        lladdr.emplace(stdplus::fromStr<stdplus::EtherAddr>(macAddress));
    }
    catch (const std::exception& e)
    {
        lg2::error("Not a valid MAC address {NET_MAC}: {ERROR}", "NET_MAC",
                   macAddress, "ERROR", e);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("macAddress"),
                              Argument::ARGUMENT_VALUE(macAddress.c_str()));
    }

    auto it = staticNeighbors.find(*addr);
    if (it == staticNeighbors.end())
    {
        it = std::get<0>(staticNeighbors.emplace(
            *addr, std::make_unique<Neighbor>(
                       bus, std::string_view(objPath), *this, *addr, *lladdr,
                       prefixLength, Neighbor::State::Permanent)));
#ifdef AMI_IP_ADVANCED_ROUTING_SUPPORT
        manager.get().addReloadPostHook([&]() {
            stdplus::In4Addr* inaddr =
                std::get_if<stdplus::In4Addr>(&(addr.value()));
            if (inaddr != nullptr)
            {
                execute("/usr/bin/ipv4-advanced-route.sh",
                        "ipv4-advanced-route.sh", interfaceName().c_str(),
                        "UP");
            }
            else
            {
                execute("/usr/bin/ipv6-advanced-route.sh",
                        "ipv6-advanced-route.sh", interfaceName().c_str(),
                        "UP");
            }
        });
#endif
    }
    else
    {
        auto str = stdplus::toStr(*lladdr);
        if (it->second->macAddress() == str)
        {
            return it->second->getObjPath();
        }
        it->second->NeighborObj::macAddress(str);
        it->second->NeighborObj::prefixLength(prefixLength);
    }

    writeConfigurationFile();
    manager.get().reloadConfigs();

    return it->second->getObjPath();
}

bool EthernetInterface::ipv6AcceptRA(bool value)
{
    if (ipv6AcceptRA() != EthernetInterfaceIntf::ipv6AcceptRA(value))
    {
        writeConfigurationFile();
        manager.get().reloadConfigs();
    }
    return value;
}

bool EthernetInterface::dhcp4(bool value)
{
    if (!EthernetInterface::ipv4Enable())
    {
        log<level::ERR>(
            fmt::format(
                "Not support in current state. IPv4 of {} is not enabled.\n",
                interfaceName())
                .c_str());
        elog<NotAllowed>(NotAllowedArgument::REASON(
            fmt::format(
                "Not support in current state. IPv4 of {} is not enabled.\n",
                interfaceName())
                .c_str()));
    }

    if (dhcp4() != value)
    {
        if (value)
        {
            for (auto& addr : addrs)
            {
                if (addr.second->type() == IP::Protocol::IPv4)
                {
                    addr.second->delete_();
                    break;
                }
            }

            if (!EthernetInterfaceIntf::defaultGateway().empty())
            {
                manager.get().removeNeighbor(
                    NeighborInfo{.ifidx = ifIdx,
                                 .state = NUD_PERMANENT,
                                 .addr = stdplus::fromStr<stdplus::In4Addr>(
                                     EthernetInterfaceIntf::defaultGateway())});
            }

            ipv4IndexUsedList.clear();
            ipv4IndexUsedList.assign(IPV4_MAX_NUM + 1, std::nullopt);
            EthernetInterfaceIntf::backupGateway({});
        }
        else
        {
            for (auto& addr : addrs)
            {
                if (addr.second->type() == IP::Protocol::IPv4)
                {
                    addr.second->delete_();
                    break;
                }
            }
        }
        EthernetInterfaceIntf::dhcp4(value);
        writeConfigurationFile();
        writeIfaceStateFile(interfaceName());
        manager.get().reloadConfigs();
    }
    return value;
}

bool EthernetInterface::dhcp6(bool value)
{
    if (!EthernetInterface::ipv6Enable())
    {
        log<level::ERR>(
            fmt::format(
                "Not support in current state. IPv6 of {} is not enabled.\n",
                interfaceName())
                .c_str());
        elog<NotAllowed>(NotAllowedArgument::REASON(
            fmt::format(
                "Not support in current state. IPv6 of {} is not enabled.\n",
                interfaceName())
                .c_str()));
    }
    if (dhcp6() != EthernetInterfaceIntf::dhcp6(value))
    {
        if (value)
        {
            ipv6IndexUsedList.clear();
            ipv6IndexUsedList.assign(IPV6_MAX_NUM + 1, std::nullopt);
	    EthernetInterfaceIntf::ipv6AcceptRA(true);
        } // if

        manager.get().addReloadPostHook([&]() {
            auto size = addrs.size();
            for (int i = 0; i < size; i++)
            {
                for (auto it = addrs.begin(); it != addrs.end(); it++)
                {
                    if (it->second->type() == IP::Protocol::IPv6 &&
                        it->second->origin() != IP::AddressOrigin::LinkLocal)
                    {
                        if ((dhcp6() && it->second->origin() ==
                                            IP::AddressOrigin::Static) ||
                            (!dhcp6() &&
                             it->second->origin() == IP::AddressOrigin::DHCP))
                        {
                            it->second->delete_();
                            break;
                        }
                    }
                }
            }
        });

        writeConfigurationFile();
        manager.get().reloadConfigs();
    }
    return value;
}

std::vector<std::string> EthernetInterface::domainName(
    std::vector<std::string> value)
{
    bool different = false;

    if (value.size() != domainName().size())
    {
        different = true;
    }
    else
    {
        for (int i = 0; i < (int)domainName().size(); i++)
        {
            if (value.at(i) != domainName().at(i))
            {
                different = true;
            }
        }
    }

    if (different)
    {
        EthernetInterfaceIntf::domainName(value);
        writeConfigurationFile();
        manager.get().reloadConfigs();
        return value;
    }
    else
    {
        return domainName();
    }
}

EthernetInterface::DHCPConf EthernetInterface::dhcpEnabled(DHCPConf value)
{
    auto old4 = EthernetInterfaceIntf::dhcp4();
    auto new4 = EthernetInterfaceIntf::dhcp4(
        value == DHCPConf::v4 || value == DHCPConf::v4v6stateless ||
        value == DHCPConf::both);
    auto old6 = EthernetInterfaceIntf::dhcp6();
    auto new6 = EthernetInterfaceIntf::dhcp6(
        value == DHCPConf::v6 || value == DHCPConf::both);

    if (old4 != new4 || old6 != new6)
    {
        if (EthernetInterfaceIntf::dhcp6() && old6 != new6)
        {
            EthernetInterfaceIntf::ipv6AcceptRA(true);
            EthernetInterfaceIntf::ipv6EnableStaticRtr(false);
            if (!EthernetInterfaceIntf::ipv6StaticRtrAddr().empty())
            {
                if (auto it =
                        staticNeighbors.find(stdplus::fromStr<stdplus::In6Addr>(
                            EthernetInterfaceIntf::ipv6StaticRtrAddr()));
                    it != staticNeighbors.end())
                {
                    staticNeighbors.erase(stdplus::fromStr<stdplus::In6Addr>(
                        EthernetInterfaceIntf::ipv6StaticRtrAddr()));
                    EthernetInterfaceIntf::ipv6StaticRtrAddr(std::string{});
                }
            }

            if (!EthernetInterfaceIntf::ipv6StaticRtr2Addr().empty())
            {
                if (auto it =
                        staticNeighbors.find(stdplus::fromStr<stdplus::In6Addr>(
                            EthernetInterfaceIntf::ipv6StaticRtr2Addr()));
                    it != staticNeighbors.end())
                {
                    staticNeighbors.erase(stdplus::fromStr<stdplus::In6Addr>(
                        EthernetInterfaceIntf::ipv6StaticRtr2Addr()));
                    EthernetInterfaceIntf::ipv6StaticRtr2Addr(std::string{});
                }
            }

            ipv6IndexUsedList.clear();
            ipv6IndexUsedList.assign(IPV6_MAX_NUM + 1, std::nullopt);
        }

        if (EthernetInterfaceIntf::dhcp4() && old4 != new4)
        {
            ipv4IndexUsedList.clear();
            ipv4IndexUsedList.assign(IPV4_MAX_NUM + 1, std::nullopt);
        }

        writeConfigurationFile();
        manager.get().reloadConfigs();
    }
    return value;
}

EthernetInterface::DHCPConf EthernetInterface::dhcpEnabled() const
{
    if (dhcp6())
    {
        return dhcp4() ? DHCPConf::both : DHCPConf::v6;
    }
    else if (dhcp4())
    {
        return ipv6AcceptRA() ? DHCPConf::v4v6stateless : DHCPConf::v4;
    }
    return ipv6AcceptRA() ? DHCPConf::v6stateless : DHCPConf::none;
}

size_t EthernetInterface::mtu(size_t value)
{
    const size_t old = EthernetInterfaceIntf::mtu();
    if (value == old)
    {
        return value;
    }

    if (value < 1280)
    {
        log<level::ERR>(fmt::format("The MTU of {} must larget than 1280.\n",
                                    interfaceName())
                            .c_str());
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("MTU"),
            Argument::ARGUMENT_VALUE(std::to_string(value).c_str()));
    }
    const auto ifname = interfaceName();
    system::setMTU(ifname, value);
    return EthernetInterfaceIntf::mtu(value);
}

bool EthernetInterface::nicEnabled(bool value)
{
    if (value == EthernetInterfaceIntf::nicEnabled())
    {
        return value;
    }

    EthernetInterfaceIntf::nicEnabled(value);
    writeNicConfiguration(value);
    if (!value)
    {
        // We only need to bring down the interface, networkd will always bring
        // up managed interfaces
        manager.get().addReloadPreHook([ifname = interfaceName()]() {
            system::setNICUp(ifname, false);
        });
    }
    else
    {
        manager.get().addReloadPreHook([ifname = interfaceName()]() {
            system::setNICUp(ifname, true);
        });
    }
    manager.get().reloadConfigs();

    return value;
}

ServerList EthernetInterface::staticNameServers(ServerList value)
{
    std::vector<std::string> dnsUniqueValues;

    for (auto& ip : value)
    {
        try
        {
            ip = stdplus::toStr(stdplus::fromStr<stdplus::InAnyAddr>(ip));
        }
        catch (const std::exception& e)
        {
            lg2::error("Not a valid IP address {NET_IP}: {ERROR}", "NET_IP", ip,
                       "ERROR", e);
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("StaticNameserver"),
                                  Argument::ARGUMENT_VALUE(ip.c_str()));
            return {};
        }

        if (ip.find(":") != std::string::npos && dhcp6Conf->dnsEnabled())
        {
            lg2::error("Not support in current state: DHCP DNS is Enabled");
            elog<NotAllowed>(
                NotAllowedArgument::REASON("Not support in current state"));
        }
        else if (ip.find(":") == std::string::npos && dhcp4Conf->dnsEnabled())
        {
            lg2::error("Not support in current state: DHCP DNS is Enabled");
            elog<NotAllowed>(
                NotAllowedArgument::REASON("Not support in current state"));
        }
        if (std::find(dnsUniqueValues.begin(), dnsUniqueValues.end(), ip) ==
            dnsUniqueValues.end())
        {
            dnsUniqueValues.push_back(ip);
        }
    }

    value =
        EthernetInterfaceIntf::staticNameServers(std::move(dnsUniqueValues));

    writeConfigurationFile();
    manager.get().reloadConfigs();

    return value;
}

void EthernetInterface::loadNTPServers(const config::Parser& config)
{
    ServerList servers = getNTPServerFromTimeSyncd();
    EthernetInterfaceIntf::ntpServers(servers);
    if (!servers.empty())
    {
        EthernetInterfaceIntf::staticNTPServers(servers);
    }
    else
    {
        EthernetInterfaceIntf::staticNTPServers({STATIC_NTP_SERVER});
    }
}

void EthernetInterface::loadNameServers(const config::Parser& config)
{
    // if (manager.get().getDHCPConf().dnsEnabled())
    //     EthernetInterfaceIntf::nameservers(getNameServerFromResolvd());
    EthernetInterfaceIntf::staticNameServers(
        config.map.getValueStrings("Network", "DNS"));
}

void EthernetInterface::loadDomainNames()
{
    EthernetInterfaceIntf::domainName(getDomainNamesFromResolvd());
}

ServerList EthernetInterface::getNTPServerFromTimeSyncd()
{
    ServerList servers; // Variable to capture the NTP Server IPs
    auto method =
        bus.get().new_method_call(TIMESYNCD_SERVICE, TIMESYNCD_SERVICE_PATH,
                                  PROPERTY_INTERFACE, METHOD_GET);

    method.append(TIMESYNCD_INTERFACE, "LinkNTPServers");

    try
    {
        auto reply = bus.get().call(method);
        std::variant<ServerList> response;
        reply.read(response);
        servers = std::get<ServerList>(response);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        lg2::error("Failed to get NTP server information from "
                   "systemd-timesyncd: {ERROR}",
                   "ERROR", e);
    }

    return servers;
}

uint8_t EthernetInterface::getIfIdx()
{
    return ifIdx;
}

ServerList EthernetInterface::nameservers() const
{
    return getNameServerFromResolvd();
}

ServerList EthernetInterface::getNameServerFromResolvd() const
{
    ServerList servers;
    auto OBJ_PATH = std::format("{}{}", RESOLVED_SERVICE_PATH, ifIdx);

    /*
      The DNS property under org.freedesktop.resolve1.Link interface contains
      an array containing all DNS servers currently used by resolved. It
      contains similar information as the DNS server data written to
      /run/systemd/resolve/resolv.conf.

      Each structure in the array consists of a numeric network interface index,
      an address family, and a byte array containing the DNS server address
      (either 4 bytes in length for IPv4 or 16 bytes in lengths for IPv6).
      The array contains DNS servers configured system-wide, including those
      possibly read from a foreign /etc/resolv.conf or the DNS= setting in
      /etc/systemd/resolved.conf, as well as per-interface DNS server
      information either retrieved from systemd-networkd or configured by
      external software via SetLinkDNS().
    */

    using type = std::vector<std::tuple<int32_t, std::vector<uint8_t>>>;
    std::variant<type> name; // Variable to capture the DNS property
    auto method = bus.get().new_method_call(RESOLVED_SERVICE, OBJ_PATH.c_str(),
                                            PROPERTY_INTERFACE, METHOD_GET);

    method.append(RESOLVED_INTERFACE, "DNS");

    try
    {
        auto reply = bus.get().call(method);
        reply.read(name);
    }
    catch (const sdbusplus::exception_t& e)
    {
        lg2::error(
            "Failed to get DNS information from systemd-resolved: {ERROR}",
            "ERROR", e);
    }
    auto tupleVector = std::get_if<type>(&name);
    for (auto i = tupleVector->begin(); i != tupleVector->end(); ++i)
    {
        int addressFamily = std::get<0>(*i);
        std::vector<uint8_t>& ipaddress = std::get<1>(*i);
        servers.push_back(stdplus::toStr(
            addrFromBuf(addressFamily, stdplus::raw::asView<char>(ipaddress))));
    }
    return servers;
}

ObjectPath EthernetInterface::createVLAN(uint16_t id)
{
    auto idStr = stdplus::toStr(id);
    auto intfName = stdplus::strCat(interfaceName(), "."sv, idStr);
    if (manager.get().interfaces.find(intfName) !=
        manager.get().interfaces.end())
    {
        lg2::error("VLAN {NET_VLAN} already exists", "NET_VLAN", id);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("VLANId"),
                              Argument::ARGUMENT_VALUE(idStr.c_str()));
    }

    if (auto size = getCreatedVLANNum(config::pathForIntfConf(
            manager.get().getConfDir(), interfaceName()));
        size >= VLAN_MAX_NUM)
    {
        log<level::ERR>(
            fmt::format(
                "There are already {} VLAN interfaces. so not create VLAN with vid {}",
                VLAN_MAX_NUM, id)
                .c_str());
        elog<NotAllowed>(NotAllowedArgument::REASON(
            fmt::format(
                "There are already {} VLAN interfaces. so not create VLAN with vid {}",
                VLAN_MAX_NUM, id)
                .c_str()));
    }

    auto objRoot = std::string_view(objPath).substr(0, objPath.rfind('/'));
    auto macStr = MacAddressIntf::macAddress();
    std::optional<stdplus::EtherAddr> mac;
    if (!macStr.empty())
    {
        mac.emplace(stdplus::fromStr<stdplus::EtherAddr>(macStr));
    }
    auto info = AllIntfInfo{InterfaceInfo{
        .type = ARPHRD_ETHER,
        .idx = 0, // TODO: Query the correct value after creation
        .flags = 0,
        .name = intfName,
        .mac = std::move(mac),
        .mtu = mtu(),
        .parent_idx = ifIdx,
        .vlan_id = id,
    }};

    // Pass the parents nicEnabled property, so that the child
    // VLAN interface can inherit.
    auto vlanIntf = std::make_unique<EthernetInterface>(
        bus, manager, info, objRoot, config::Parser(), nicEnabled());
    ObjectPath ret = vlanIntf->objPath;

    vlanIntf->writeConfigurationFile();
    manager.get().interfaces.emplace(intfName, std::move(vlanIntf));

    // write the device file for the vlan interface.
    config::Parser config;
    auto& netdev = config.map["NetDev"].emplace_back();
    netdev["Name"].emplace_back(intfName);
    netdev["Kind"].emplace_back("vlan");
    config.map["VLAN"].emplace_back()["Id"].emplace_back(std::move(idStr));
    config.writeFile(
        config::pathForIntfDev(manager.get().getConfDir(), intfName));

    manager.get().addReloadPostHook([ifname = interfaceName()]() {
        execute("/bin/systemctl", "systemctl", "restart",
                fmt::format("phosphor-ipmi-net@{}.service", ifname).c_str());
    });

    writeConfigurationFile();
    manager.get().reloadConfigs();

    return ret;
}
#if ENABLE_BOND_SUPPORT
ObjectPath EthernetInterface::createBond(std::string activeSlave,
                                         uint8_t miiMonitor)
{
    for (const auto& [_, intf] : manager.get().interfaces)
    {
        if (intf->interfaceName().find(".") != std::string::npos)
        {
            log<level::ERR>("Bond cannot be enabled as VLAN is enabled");
            elog<NotAllowed>(NotAllowedArgument::REASON(
                "Bond cannot be enabled as VLAN is enabled"));
        }
    }

    auto intfName = bondIfcName;
    std::string macStr{}, ipv6StaticRtrAddr{};
    std::optional<stdplus::In4Addr> gw = std::nullopt;
    std::optional<stdplus::In6Addr> gw6 = std::nullopt;
    bool ipv4Enable, ipv6Enable, ipv6EnableStaticRtr;
    std::vector<std::optional<std::string>> ipv4IndexUsedList,
        ipv6IndexUsedList;
    if (manager.get().interfaces.find(intfName) !=
        manager.get().interfaces.end())
    {
        log<level::ERR>("Bond already exists");
    }

    auto objRoot = std::string_view(objPath).substr(0, objPath.rfind('/'));

    for (const auto& [_, intf] : manager.get().interfaces)
    {
        if (intf->interfaceName().compare(activeSlave.c_str()) == 0)
        {
            /*Get Information of Active Slave*/
            macStr = intf->macAddress();
            ipv4IndexUsedList = intf->ipv4IndexUsedList;
            ipv6IndexUsedList = intf->ipv6IndexUsedList;
            ipv4Enable = intf->ipv4Enable();
            ipv6Enable = intf->ipv6Enable();
            ipv6EnableStaticRtr = intf->ipv6EnableStaticRtr();
            ipv6StaticRtrAddr = intf->ipv6StaticRtrAddr();
            if (!intf->defaultGateway().empty())
            {
                gw = stdplus::fromStr<stdplus::In4Addr>(intf->defaultGateway());
            }
            if (!intf->defaultGateway6().empty())
            {
                gw6 =
                    stdplus::fromStr<stdplus::In6Addr>(intf->defaultGateway6());
            }
        }
    }

    manager.get().writeToConfigurationFile();

    std::optional<ether_addr> mac;
    if (!macStr.empty())
    {
        mac.emplace(stdplus::fromStr<stdplus::EtherAddr>(macStr));
    }

    std::optional<BondInfo> bondinfo;
    bondinfo.emplace(activeSlave, 1, miiMonitor); /*Mode - active-backup = 1*/

    auto info = AllIntfInfo{InterfaceInfo{
        .idx = 0, // TODO: Query the correct value after creation
        .flags = 0,
        .name = intfName,
        .mac = std::move(mac),
        .mtu = mtu(),
        .parent_idx = ifIdx,
        .bondInfo = std::move(bondinfo),
    }};

    if (gw.has_value())
    {
        info.defgw4 = gw;
    }

    if (gw6.has_value())
    {
        info.defgw6 = gw6;
    }
    // Pass the parents nicEnabled property, so that the child
    // Bond interface can inherit.
    auto bondIntf = std::make_unique<EthernetInterface>(
        bus, manager, info, objRoot,
        config::Parser(config::pathForIntfConf(
            manager.get().getConfDir(), info.intf.bondInfo->activeSlave)),
        nicEnabled());

    ObjectPath ret = bondIntf->objPath;

    manager.get().interfaces.emplace(intfName, std::move(bondIntf));

    // write the device file for the bond interface.
    config::Parser config;
    auto& netdev = config.map["NetDev"].emplace_back();
    netdev["Name"].emplace_back(intfName);
    netdev["Kind"].emplace_back("bond");
    netdev["MACAddress"].emplace_back(macStr);
    netdev["MACAddressPolicy"].emplace_back("persistent");
    auto& bond = config.map["Bond"].emplace_back();
    bond["Mode"].emplace_back("active-backup");
    bond["MIIMonitorSec"].emplace_back(fmt::format("{}ms", miiMonitor));

    config.writeFile(
        config::pathForIntfDev(manager.get().getConfDir(), intfName));

    manager.get().writeToConfigurationFile();

    /** Restore Information of Active Slave*/
    if (auto it = manager.get().interfaces.find(bondIfcName);
        it != manager.get().interfaces.end())
    {
        it->second->EthernetInterfaceIntf::ipv4Enable(ipv4Enable, true);
        it->second->EthernetInterfaceIntf::ipv6Enable(ipv6Enable, true);
        it->second->ipv4IndexUsedList = std::move(ipv4IndexUsedList);
        it->second->ipv6IndexUsedList = std::move(ipv6IndexUsedList);
        it->second->EthernetInterfaceIntf::ipv6EnableStaticRtr(
            ipv6EnableStaticRtr, true);
        it->second->EthernetInterfaceIntf::ipv6StaticRtrAddr(ipv6StaticRtrAddr,
                                                             true);
        it->second->bonding->writeBondConfiguration(true);
    }

    writeIfaceStateFile(intfName);
    execute("/bin/systemctl", "systemctl", "restart",
            "systemd-networkd.service");

    manager.get().addReloadPostHook([&]() {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        execute("/bin/systemctl", "systemctl", "restart",
                "phosphor-ipmi-net@bond0.service");
    });
    manager.get().reloadConfigs();
    return ret;
}
#endif
ServerList EthernetInterface::staticNTPServers(ServerList value)
{
    value = EthernetInterfaceIntf::staticNTPServers(std::move(value));

    writeConfigurationFile();
    manager.get().reloadConfigs();

    return value;
}

void EthernetInterface::writeIfaceStateFile(std::string ifname)
{
    config::Parser IfaceState;
    auto it = manager.get().interfaces.find(ifname);
    if (it == manager.get().interfaces.end())
    {
        log<level::ERR>(
            fmt::format("No matching interface name: {}", ifname).c_str());
        return;
    }
    {
        auto& state = IfaceState.map["Network"].emplace_back();
        state["IPv4Enable"].emplace_back(
            it->second->EthernetInterfaceIntf::ipv4Enable() ? "true" : "false");
        state["IPv6Enable"].emplace_back(
            it->second->EthernetInterfaceIntf::ipv6Enable() ? "true" : "false");

        auto& router = IfaceState.map["IPv6Router"].emplace_back();
        router["IPv6EnableStaticRtr"].emplace_back(
            it->second->EthernetInterfaceIntf::ipv6EnableStaticRtr()
                ? "true"
                : "false");
        if (EthernetInterfaceIntf::ipv6EnableStaticRtr())
        {
            router["IPv6StaticRtrAddr"].emplace_back(
                it->second->EthernetInterfaceIntf::ipv6StaticRtrAddr());
            if (!EthernetInterfaceIntf::ipv6StaticRtrAddr().empty())
            {
                if (auto itt = it->second->staticNeighbors.find(
                        stdplus::fromStr<stdplus::In6Addr>(
                            it->second
                                ->EthernetInterfaceIntf::ipv6StaticRtrAddr()));
                    itt != it->second->staticNeighbors.end())
                {
                    router["IPv6StaticRtrPrefix"].emplace_back(
                        stdplus::toStr((itt->second->prefixLength())));
                }
            }

            router["IPv6StaticRtr2Addr"].emplace_back(
                it->second->EthernetInterfaceIntf::ipv6StaticRtr2Addr());
            if (!EthernetInterfaceIntf::ipv6StaticRtr2Addr().empty())
            {
                if (auto itt = it->second->staticNeighbors.find(
                        stdplus::fromStr<stdplus::In6Addr>(
                            it->second
                                ->EthernetInterfaceIntf::ipv6StaticRtr2Addr()));
                    itt != it->second->staticNeighbors.end())
                {
                    router["IPv6StaticRtr2Prefix"].emplace_back(
                        stdplus::toStr((itt->second->prefixLength())));
                }
            }
        }
    }
    {
        if (!it->second->dhcp4() || !it->second->dhcp6())
        {
            auto& index = IfaceState.map["Address"].emplace_back()["Index"];
            if (!it->second->dhcp4() &&
                it->second->EthernetInterfaceIntf::ipv4Enable())
            {
                for (auto i = 0; i < it->second->ipv4IndexUsedList.size(); i++)
                {
                    if (it->second->ipv4IndexUsedList.at(i).has_value())
                    {
                        index.emplace_back(fmt::format(
                            "{}/{}",
                            it->second->ipv4IndexUsedList.at(i).value(), i));
                    }
                } // for

                auto& gateway4route = IfaceState.map["Route"].emplace_back();

                auto backupgateway4 = EthernetInterfaceIntf::backupGateway();
                if (!backupgateway4.empty())
                {
                    gateway4route["BackupGateway"].emplace_back(backupgateway4);
                }

                auto defaultgateway4 = EthernetInterfaceIntf::defaultGateway();
                if (!defaultgateway4.empty())
                {
                    gateway4route["DefaultGateway"].emplace_back(
                        defaultgateway4);
                }
            } // if

            if (!it->second->dhcp6() &&
                it->second->EthernetInterfaceIntf::ipv6Enable())
            {
                for (auto i = 0; i < it->second->ipv6IndexUsedList.size(); i++)
                {
                    if (it->second->ipv6IndexUsedList.at(i).has_value())
                    {
                        index.emplace_back(fmt::format(
                            "{}/{}",
                            it->second->ipv6IndexUsedList.at(i).value(), i));
                    }
                } // for
            } // if
        } // if
    }
    {
        if (!it->second->autoNeg())
        {
            auto& link = IfaceState.map["Link"].emplace_back();
            link["AutoNeg"].emplace_back("false");
            link["Duplex"].emplace_back(
                static_cast<uint8_t>(it->second->duplex()) ? "full" : "half");
            link["Speed"].emplace_back(std::to_string(it->second->speed()));
        }
    }
#if AMI_NCSI_SUPPORT
    {
        {
            if (std::string{DEFAULT_NCSI_INTERFACE}.find(interfaceName()) !=
                    std::string::npos &&
                EthernetInterface::ncsiConfig.has_value())
            {
                auto& ncsi = IfaceState.map["NCSI"].emplace_back();
                ncsi["Mode"].emplace_back(
                    EthernetInterface::ncsiConfig.value().mode() ==
                            NCSIIface::Mode::Auto
                        ? "Auto"
                        : "Manual");
                ncsi["Package"].emplace_back(std::to_string(
                    EthernetInterface::ncsiConfig.value().package()));
                ncsi["Channel"].emplace_back(std::to_string(
                    EthernetInterface::ncsiConfig.value().channel()));
            }
        }
    }
#endif
    {
        std::vector<uint8_t> value =
            EthernetInterfaceIntf::dhcpv6TimingConfParam();
        if (!value.empty())
        {
            auto it = value.begin();

            auto& dhcp6TimingConf =
                IfaceState.map["DHCPv6TimingConf"].emplace_back();

            dhcp6TimingConf["SOLMaxDelay"].emplace_back(
                fmt::format("{}", *it++));

            dhcp6TimingConf["SOLTimeout"].emplace_back(
                fmt::format("{}", *it++));

            dhcp6TimingConf["SOLMaxRt"].emplace_back(fmt::format("{}", *it++));

            dhcp6TimingConf["REQTimeout"].emplace_back(
                fmt::format("{}", *it++));

            dhcp6TimingConf["REQMaxRt"].emplace_back(fmt::format("{}", *it++));

            dhcp6TimingConf["REQMaxRc"].emplace_back(fmt::format("{}", *it++));

            dhcp6TimingConf["RENTimeout"].emplace_back(
                fmt::format("{}", *it++));

            dhcp6TimingConf["RENMaxRt"].emplace_back(fmt::format("{}", *it++));

            dhcp6TimingConf["REBTimeout"].emplace_back(
                fmt::format("{}", *it++));

            dhcp6TimingConf["REBMaxRt"].emplace_back(fmt::format("{}", *it++));

            dhcp6TimingConf["INFTimeout"].emplace_back(
                fmt::format("{}", *it++));

            dhcp6TimingConf["INFMaxRt"].emplace_back(fmt::format("{}", *it));
        }
    }

    {
        std::vector<uint8_t> value =
            EthernetInterfaceIntf::ipv6SLAACTimingConfParam();
        if (!value.empty())
        {
            auto it = value.begin();

            auto& slaacTimingConf =
                IfaceState.map["SLAACTimingConf"].emplace_back();

            slaacTimingConf["MaxRtrSolicitationDelay"].emplace_back(
                fmt::format("{}", *it++));

            slaacTimingConf["RtrSolicitationInterval"].emplace_back(
                fmt::format("{}", *it++));

            slaacTimingConf["MaxRtrSolicitations"].emplace_back(
                fmt::format("{}", *it++));

            slaacTimingConf["DupAddrDetectTransmits"].emplace_back(
                fmt::format("{}", *it++));

            slaacTimingConf["MaxMulticastSolicit"].emplace_back(
                fmt::format("{}", *it++));

            slaacTimingConf["MaxUnicastSolicit"].emplace_back(
                fmt::format("{}", *it++));

            slaacTimingConf["MaxAnycastDelayTime"].emplace_back(
                fmt::format("{}", *it++));

            slaacTimingConf["MaxNeighborAdvertisement"].emplace_back(
                fmt::format("{}", *it++));

            slaacTimingConf["ReachableTime"].emplace_back(
                fmt::format("{}", *it++));

            slaacTimingConf["RetransTimer"].emplace_back(
                fmt::format("{}", *it++));

            slaacTimingConf["DelayFirstProbeTime"].emplace_back(
                fmt::format("{}", *it++));
        }
    }

    IfaceState.writeFile(fs::path{
        fmt::format("{}/{}", manager.get().ifaceConfDir.generic_string(),
                    ifname)
            .c_str()});
    lg2::info("Wrote networkd file: {CFG_FILE}", "CFG_FILE",
              fs::path{fmt::format("{}/{}",
                                   manager.get().ifaceConfDir.generic_string(),
                                   ifname)
                           .c_str()});
}

ServerList EthernetInterface::ntpServers(ServerList /*servers*/)
{
    elog<NotAllowed>(NotAllowedArgument::REASON("ReadOnly Property"));
}

void EthernetInterface::writeNicConfiguration(bool isActive)
{
    std::ifstream ifs(
        config::pathForIntfConf(manager.get().getConfDir(), interfaceName()));
    std::string line;
    std::vector<std::string> vec;
    if (!ifs.is_open())
    {
        log<level::INFO>(
            fmt::format("writeNicConfiguration {} file not opened.\n",
                        config::pathForIntfConf(manager.get().getConfDir(),
                                                interfaceName())
                            .generic_string())
                .c_str());
    }

    if (isActive)
    {
        while (ifs.peek() != EOF)
        {
            std::getline(ifs, line);
            if (!line.starts_with("Unmanaged"))
            {
                vec.push_back(line);
            }

            line.clear();
        }
    }
    else
    {
        while (ifs.peek() != EOF)
        {
            std::getline(ifs, line);
            vec.push_back(line);
            if (line.starts_with("[Link]"))
            {
                vec.push_back("Unmanaged=yes");
            }

            line.clear();
        }
    }

    ifs.close();
    std::ofstream ofs(
        config::pathForIntfConf(manager.get().getConfDir(), interfaceName()));
    for (auto& v : vec)
    {
        ofs << v << std::endl;
    }

    ofs.flush();
    ofs.close();
}

static constexpr std::string_view tfStr(bool value)
{
    return value ? "true"sv : "false"sv;
}

static void writeUpdatedTime(const Manager& manager,
                             const std::filesystem::path& netFile)
{
    // JFFS2 doesn't have the time granularity to deal with sub-second
    // updates. Since we can have multiple file updates within a second
    // around a reload, we need a location which gives that precision for
    // future networkd detected reloads. TMPFS gives us this property.
    if (manager.getConfDir() == "/etc/systemd/network"sv)
    {
        auto dir = stdplus::strCat(netFile.native(), ".d");
        dir.replace(1, 3, "run"); // Replace /etc with /run
        auto file = dir + "/updated.conf";
        try
        {
            std::filesystem::create_directories(dir);
            using namespace stdplus::fd;
            futimens(
                open(file,
                     OpenFlags(OpenAccess::WriteOnly).set(OpenFlag::Create),
                     0644)
                    .get(),
                nullptr);
        }
        catch (const std::exception& e)
        {
            lg2::error("Failed to write time updated file {FILE}: {ERROR}",
                       "FILE", file, "ERROR", e.what());
        }
    }
}

void EthernetInterface::writeConfigurationFile()
{
    config::Parser config;
#if ENABLE_BOND_SUPPORT
    auto it = manager.get().interfaces.find(bondIfcName);

    if ((it != manager.get().interfaces.end()) &&
        (interfaceName().compare(bondIfcName) != 0) &&
        (interfaceName().compare("hostusb0") != 0))
    {
        std::error_code ec{};
        if (fs::exists(config::pathForIntfConf(manager.get().getConfDir(),
                                               interfaceName()),
                       ec) &&
            (!fs::exists(
                config::pathForIntfConf(manager.get().getBondingConfBakDir(),
                                        interfaceName()),
                ec)))
        {
            if (!fs::copy_file(
                    config::pathForIntfConf(manager.get().getConfDir(),
                                            interfaceName()),
                    config::pathForIntfConf(
                        manager.get().getBondingConfBakDir(), interfaceName()),
                    fs::copy_options::overwrite_existing, ec))
            {
                log<level::INFO>(
                    fmt::format("interfaceName = {}, error message = {}\n",
                                __LINE__, interfaceName(), ec.message())
                        .c_str());
            }
        }
        else
        {
            log<level::INFO>(
                fmt::format("interfaceName = {}, error message = {}\n",
                            __LINE__, interfaceName(), ec.message())
                    .c_str());
        }

        config.map["Match"].emplace_back()["Name"].emplace_back(
            interfaceName());
        {
            auto& link = config.map["Link"].emplace_back();

            if (!EthernetInterfaceIntf::nicEnabled())
            {
                link["Unmanaged"].emplace_back("yes");
            }
        }
        auto& network = config.map["Network"].emplace_back();
        {
            auto& bond = network["Bond"];
            bond.emplace_back(bondIfcName);
            if (interfaceName().compare(it->second->bonding->activeSlave()) ==
                0)
            {
                network["PrimarySlave"].emplace_back("true");
            }
        }
        {
            writeIfaceStateFile(interfaceName());
        }
    }
    else
#endif
    {
        config.map["Match"].emplace_back()["Name"].emplace_back(
            interfaceName());
        {
            auto& link = config.map["Link"].emplace_back();
#if PERSIST_MAC
            auto mac = MacAddressIntf::macAddress();
            if (!mac.empty())
            {
                link["MACAddress"].emplace_back(mac);
            }
#endif
            if (!EthernetInterfaceIntf::nicEnabled())
            {
                link["Unmanaged"].emplace_back("yes");
            }
        }
        {
            auto& network = config.map["Network"].emplace_back();
            {
                auto& lla = network["LinkLocalAddressing"];
#ifdef IPV4_LINK_LOCAL
                lla.emplace_back("ipv4");
#endif
#ifdef IPV6_LINK_LOCAL
                lla.emplace_back("ipv6");
#endif
#ifdef IPV4_IPV6_LINK_LOCAL
                lla.emplace_back("true");
#endif
#ifdef DISABLE_LINK_LOCAL
                lla.emplace_back("false");
#endif
            }

            writeIfaceStateFile(interfaceName());

            network["IPv6AcceptRA"].emplace_back(
                EthernetInterfaceIntf::ipv6Enable() && ipv6AcceptRA()
                    ? "true"
                    : "false");
            network["DHCP"].emplace_back(
                dhcp4() ? (dhcp6() ? "true" : "ipv4")
                        : (dhcp6() ? "ipv6" : "false"));
            {
                if (int size = domainName().size(); size > 0)
                {
                    std::string s("");
                    for (int i = 0; i < size; i++)
                    {
                        s += domainName().at(i) + " ";
                    }
                    network["Domains"].emplace_back(s);
                }
            }
            {
                auto& vlans = network["VLAN"];
                for (const auto& [_, intf] : manager.get().interfaces)
                {
                    if (intf->vlan && intf->vlan->parentIdx == ifIdx)
                    {
                        vlans.emplace_back(intf->interfaceName());
                    }
                }
            }
            {
                auto& ntps = network["NTP"];
                for (const auto& ntp :
                     EthernetInterfaceIntf::staticNTPServers())
                {
                    ntps.emplace_back(ntp);
                }
            }
            {
                auto& dnss = network["DNS"];
                for (const auto& dns :
                     EthernetInterfaceIntf::staticNameServers())
                {
                    dnss.emplace_back(dns);
                }
            }
            {
                auto& address = network["Address"];
                for (const auto& addr : addrs)
                {
                    if ((addr.second->type() == IP::Protocol::IPv6 &&
                         !dhcp6() && EthernetInterfaceIntf::ipv6Enable()) ||
                        (addr.second->type() == IP::Protocol::IPv4 ||
                         !dhcp4() && EthernetInterfaceIntf::ipv4Enable()))
                    {
                        {
			    if (addr.second->origin() == IP::AddressOrigin::Static)
                            {
                                address.emplace_back(
                                    fmt::format("{}/{}", addr.second->address(),
                                                addr.second->prefixLength()));
                            }
                        }
                    }
                }
            }
            {
                if (!dhcp4() && EthernetInterfaceIntf::ipv4Enable())
                {
                    auto gateway4 = EthernetInterfaceIntf::defaultGateway();
                    if (!gateway4.empty())
                    {
                        auto& gateway4route =
                            config.map["Route"].emplace_back();
                        gateway4route["Gateway"].emplace_back(gateway4);
                        gateway4route["GatewayOnLink"].emplace_back("true");
                    }

                    auto backupgateway4 =
                        EthernetInterfaceIntf::backupGateway();
                    if (!backupgateway4.empty())
                    {
                        auto& gateway4route =
                            config.map["Route"].emplace_back();
                        gateway4route["Gateway"].emplace_back(backupgateway4);
                        gateway4route["Metric"].emplace_back(fmt::format(
                            "{}", getMetricValueDefaultGateway(
                                      EthernetInterfaceIntf::defaultGateway()) +
                                      1));
                    }
                }

                if (!dhcp6() && EthernetInterfaceIntf::ipv6Enable())
                {
                    auto gateway6 = EthernetInterfaceIntf::defaultGateway6();
                    if (!gateway6.empty())
                    {
                        auto& gateway6route =
                            config.map["Route"].emplace_back();
                        gateway6route["Gateway"].emplace_back(gateway6);
                        gateway6route["GatewayOnLink"].emplace_back("true");
                    }
                }
            }
        }
        {
            auto& ipv6acceptra = config.map["IPv6AcceptRA"].emplace_back();
            ipv6acceptra["DHCPv6Client"].emplace_back(
                dhcp6() ? "true" : "false");
            ipv6acceptra["UseAutonomousPrefix"].emplace_back(
                dhcp6() ? "true" : "false");
        }
        {
            auto& neighbors = config.map["Neighbor"];
            for (const auto& sneighbor : staticNeighbors)
            {
                auto& neighbor = neighbors.emplace_back();
                neighbor["Address"].emplace_back(sneighbor.second->ipAddress());
                neighbor["MACAddress"].emplace_back(
                    sneighbor.second->macAddress());
            }
        }
        {
            auto& dhcpv6 = config.map["DHCPv6"].emplace_back();
            dhcpv6["DUIDType"].emplace_back("link-layer");
        }
        {
            dhcpv6TimingParamWriteConfFile(config);
        }
        {
            auto& dhcp4 = config.map["DHCPv4"].emplace_back();
            dhcp4["ClientIdentifier"].emplace_back("mac");
            dhcp4["UseDNS"].emplace_back(tfStr(dhcp4Conf->dnsEnabled()));
            dhcp4["UseDomains"].emplace_back(tfStr(dhcp4Conf->domainEnabled()));
            dhcp4["UseNTP"].emplace_back(tfStr(dhcp4Conf->ntpEnabled()));
            dhcp4["UseHostname"].emplace_back(
                tfStr(dhcp4Conf->hostNameEnabled()));
            dhcp4["SendHostname"].emplace_back(
                tfStr(dhcp4Conf->sendHostNameEnabled()));
            dhcp4["SendNsupdate"].emplace_back(
                tfStr(dhcp4Conf->sendHostNameEnabled()));
            if (!dhcp4Conf->vendorClassIdentifier().empty())
                dhcp4["VendorClassIdentifier"].emplace_back(
                    dhcp4Conf->vendorClassIdentifier());

            for (auto it = dhcp4Conf->vendorOptionList.begin();
                 it != dhcp4Conf->vendorOptionList.end(); it++)
            {
                dhcp4["SendVendorOption"].emplace_back(
                    fmt::format("{}:string:{}", it->first, it->second).c_str());
            }
        }
        {
            auto& dhcp6 = config.map["DHCPv6"].emplace_back();
            dhcp6["UseDNS"].emplace_back(tfStr(dhcp6Conf->dnsEnabled()));
            dhcp6["UseDomains"].emplace_back(tfStr(dhcp6Conf->domainEnabled()));
            dhcp6["UseNTP"].emplace_back(tfStr(dhcp6Conf->ntpEnabled()));
            dhcp6["UseHostname"].emplace_back(
                tfStr(dhcp6Conf->hostNameEnabled()));
            dhcp6["SendHostname"].emplace_back(
                tfStr(dhcp6Conf->sendHostNameEnabled()));
            dhcp6["SendNsupdate"].emplace_back(
                tfStr(dhcp6Conf->sendHostNameEnabled()));
        }
    }
    auto path =
        config::pathForIntfConf(manager.get().getConfDir(), interfaceName());
    config.writeFile(path);
    lg2::info("Wrote networkd file: {CFG_FILE}", "CFG_FILE", path);
    writeUpdatedTime(manager, path);
}

void writeARPControlDefault(const std::string& filename)
{
    config::Parser config;
    auto& Garp = config.map["GARP"].emplace_back();
    Garp["Interval"].emplace_back("2000");
    Garp["Enabled"].emplace_back("false");
    auto& ARPResp = config.map["ARP_Response"].emplace_back();
    ARPResp["Enabled"].emplace_back("true");
    config.writeFile(filename);
}

std::string EthernetInterface::macAddress([[maybe_unused]] std::string value)
{
    if (vlan)
    {
        lg2::error("Tried to set MAC address on VLAN");
        elog<InternalFailure>();
    }
#if PERSIST_MAC
    stdplus::EtherAddr newMAC;
    try
    {
        newMAC = stdplus::fromStr<stdplus::EtherAddr>(value);
    }
    catch (const std::exception& e)
    {
        lg2::error("MAC Address {MAC_ADDRESS} is not valid: {REASON}",
                   "MAC_ADDRESS", value, "REASON", e.what());
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("MACAddress"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }
    if (!newMAC.isUnicast())
    {
        lg2::error("MAC Address {NET_MAC} is not valid", "NET_MAC", value);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("MACAddress"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }

    auto interface = interfaceName();
    auto validMAC = stdplus::toStr(newMAC);

    // We don't need to update the system if the address is unchanged
    auto oldMAC =
        stdplus::fromStr<stdplus::EtherAddr>(MacAddressIntf::macAddress());

    std::string activeSlaveInterface = "";
#if ENABLE_BOND_SUPPORT
    auto bondEnabled = false;
#endif

#ifdef HAVE_UBOOT_ENV
    // Ensure that the valid address is stored in the u-boot-env
    auto envVar = interfaceToUbootEthAddr(interface);
    if (envVar)
    {
        // Trimming MAC addresses that are out of range. eg: AA:FF:FF:FF:FF:100;
        // and those having more than 6 bytes. eg: AA:AA:AA:AA:AA:AA:BB
        execute("/sbin/fw_setenv", "fw_setenv", envVar->c_str(),
                validMAC.c_str());
    }
#endif // HAVE_UBOOT_ENV

    if (newMAC != oldMAC)
    {
        // Update everything that depends on the MAC value
        for (const auto& [_, intf] : manager.get().interfaces)
        {
            if (intf->vlan && intf->vlan->parentIdx == ifIdx)
            {
                intf->MacAddressIntf::macAddress(validMAC);
            }
#if ENABLE_BOND_SUPPORT
            if (intf->interfaceName() == "bond0")
            {
                bondEnabled = true;
                activeSlaveInterface = intf->bonding->activeSlave();
            }
#endif
        }
#if ENABLE_BOND_SUPPORT
        manager.get().addReloadPreHook([this, bondEnabled, validMAC,
                                        activeSlaveInterface, interface,
                                        manager = manager]() {
            // handle bonding mac address update for slave and bond
            if (bondEnabled)
            {
                std::string intf = (interface == "bond0") ? "eth0" : interface;
                if (intf == activeSlaveInterface)
                {
                    for (const auto& [_, intf] : manager.get().interfaces)
                    {
                        if (intf->interfaceName() == "bond0")
                        {
                            intf->MacAddressIntf::macAddress(validMAC);
                            intf->writeConfigurationFile();
                            intf->bonding->updateMACAddress(validMAC);
                            break;
                        }
                    }
                }
                else // update mac address for slave of bonding interface when
                     // it is not active slave
                {
                    this->updateBondConfBackupForSlaveMAC(validMAC, intf);
                }
                std::this_thread::sleep_for(std::chrono::seconds(3));
                execute("/sbin/reboot", "reboot", "-f");
            }
            else
            {
                this->MacAddressIntf::macAddress(validMAC);
                this->writeConfigurationFile();
                // The MAC and LLADDRs will only update if the NIC is already
                // down
                system::setNICUp(interface, false);
            }

            writeUpdatedTime(
                manager,
                config::pathForIntfConf(manager.get().getConfDir(), interface));
        });
#else
        manager.get().addReloadPreHook([this, validMAC, interface,
                                        manager = manager]() {
            this->MacAddressIntf::macAddress(validMAC);
            this->writeConfigurationFile();
            // The MAC and LLADDRs will only update if the NIC is already down
            system::setNICUp(interface, false);
            writeUpdatedTime(
                manager,
                config::pathForIntfConf(manager.get().getConfDir(), interface));
        });
#endif
        manager.get().reloadConfigs();
    }

    return value;
#else
    elog<NotAllowed>(
        NotAllowedArgument::REASON("Writing MAC address is not allowed"));
#endif // PERSIST_MAC
}

void EthernetInterface::deleteAll()
{
    // clear all the ip on the interface
    addrs.clear();
    ipv4IndexUsedList.clear();
    ipv4IndexUsedList.assign(IPV4_MAX_NUM + 1, std::nullopt);

    ipv6IndexUsedList.clear();
    ipv6IndexUsedList.assign(IPV6_MAX_NUM + 1, std::nullopt);
    writeConfigurationFile();
    manager.get().reloadConfigs();
}

template <typename Addr>
static void normalizeGateway(std::string& gw)
{
    if (gw.empty())
    {
        return;
    }
    try
    {
        auto ip = stdplus::fromStr<Addr>(gw);
        if (ip == Addr{})
        {
            gw.clear();
            return;
        }
        if (!validIntfIP(ip))
        {
            throw std::invalid_argument("Invalid unicast");
        }

        if (typeid(stdplus::In4Addr) == typeid(Addr))
            ip_address::isValidIPv4Addr(gw, ip_address::Type::GATEWAY4_ADDRESS);
        else
            ip_address::isValidIPv6Addr(gw, ip_address::Type::GATEWAY6_ADDRESS);

        gw = stdplus::toStr(ip);
    }
    catch (const std::exception& e)
    {
        lg2::error("Invalid GW `{NET_GW}`: {ERROR}", "NET_GW", gw, "ERROR", e);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("GATEWAY"),
                              Argument::ARGUMENT_VALUE(gw.c_str()));
    }
}

std::string EthernetInterface::defaultGateway(std::string gateway)
{
    if (!EthernetInterface::ipv4Enable())
    {
        log<level::ERR>(
            fmt::format(
                "Not support in current state. IPv4 of {} is not enabled.\n",
                interfaceName())
                .c_str());
        elog<NotAllowed>(NotAllowedArgument::REASON(
            fmt::format(
                "Not support in current state. IPv4 of {} is not enabled.\n",
                interfaceName())
                .c_str()));
    }
    normalizeGateway<stdplus::In4Addr>(gateway);
    if (gateway != defaultGateway())
    {
        for (auto& addr : addrs)
        {
            if (addr.second->type() == IP::Protocol::IPv4 &&
                addr.second->origin() != IP::AddressOrigin::LinkLocal)
            {
                ip_address::isSameSeries(addr.second->address(), gateway,
                                         addr.second->prefixLength());
                break;
            }
        }

        if (!EthernetInterfaceIntf::defaultGateway().empty())
        {
            manager.get().removeNeighbor(
                NeighborInfo{.ifidx = ifIdx,
                             .state = NUD_PERMANENT,
                             .addr = stdplus::fromStr<stdplus::In4Addr>(
                                 EthernetInterfaceIntf::defaultGateway())});
        }
        gateway = EthernetInterfaceIntf::defaultGateway(std::move(gateway));
        auto [mac, prefixLength] = getDwMacAddrByIP(gateway);
        manager.get().addNeighbor(NeighborInfo{
            .ifidx = ifIdx,
            .state = NUD_PERMANENT,
            .addr = stdplus::fromStr<stdplus::In4Addr>(
                EthernetInterfaceIntf::defaultGateway()),
            .mac = stdplus::fromStr<stdplus::EtherAddr>(
                mac.value_or("00:00:00:00:00:00")),
            .prefixLength = prefixLength});
        writeConfigurationFile();
        manager.get().reloadConfigs();
    }
    return gateway;
}

std::string EthernetInterface::defaultGateway6(std::string gateway)
{
    if (!EthernetInterface::ipv6Enable())
    {
        log<level::ERR>(
            fmt::format(
                "Not support in current state. IPv6 of {} is not enabled.\n",
                interfaceName())
                .c_str());
        elog<NotAllowed>(NotAllowedArgument::REASON(
            fmt::format(
                "Not support in current state. IPv4 of {} is not enabled.\n",
                interfaceName())
                .c_str()));
    }

    try
    {
        for (auto& addr : addrs)
        {
            if (addr.second->type() != IP::Protocol::IPv6 ||
                addr.second->origin() != IP::AddressOrigin::Static)
            {
                continue;
            }
            if (gateway.compare(addr.second->address()) == 0)
            {
                log<level::ERR>("IP Address and Gateway are the same\n");
                elog<NotAllowed>(NotAllowedArgument::REASON(
                    "IP Address and Gateway are the same\n"));
            }
        }
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Wrong Gateway");
        elog<NotAllowed>(NotAllowedArgument::REASON("Wrong Gateway"));
    }

    normalizeGateway<stdplus::In6Addr>(gateway);
    if (gateway != defaultGateway6())
    {
        gateway = EthernetInterfaceIntf::defaultGateway6(std::move(gateway));
        writeConfigurationFile();
        manager.get().reloadConfigs();
    }
    return gateway;
}

EthernetInterface::VlanProperties::VlanProperties(
    sdbusplus::bus_t& bus, stdplus::const_zstring objPath,
    const InterfaceInfo& info, stdplus::PinnedRef<EthernetInterface> eth) :
    VlanIfaces(bus, objPath.c_str(), VlanIfaces::action::defer_emit),
    parentIdx(*info.parent_idx), eth(eth)
{
    VlanIntf::id(*info.vlan_id, true);
    emit_object_added();
}

void EthernetInterface::VlanProperties::delete_()
{
    eth.get().signals.clear();
    eth.get().vlanMonitorActive.store(false);

    if (eth.get().vlanMonitorThread && eth.get().vlanMonitorThread->joinable())
    {
        eth.get().vlanMonitorThread->join();
    }

    auto intf = eth.get().interfaceName();
    std::string parentIfName;

    // Remove all configs for the current interface
    const auto& confDir = eth.get().manager.get().getConfDir();
    std::error_code ec;
    std::filesystem::remove(config::pathForIntfConf(confDir, intf), ec);
    std::filesystem::remove(config::pathForIntfDev(confDir, intf), ec);

    const auto& infoDir = eth.get().manager.get().getIfaceConfDir();
    std::filesystem::remove(config::pathForIntfInfo(infoDir, intf), ec);

    if (eth.get().ifIdx > 0)
    {
        eth.get().manager.get().interfacesByIdx.erase(eth.get().ifIdx);
    }
    auto it = eth.get().manager.get().interfaces.find(intf);
    auto obj = std::move(it->second);
    eth.get().manager.get().interfaces.erase(it);

    // Write an updated parent interface since it has a VLAN entry
    for (const auto& [_, intf] : eth.get().manager.get().interfaces)
    {
        if (intf->ifIdx == parentIdx)
        {
            parentIfName = intf->interfaceName();
            intf->writeConfigurationFile();
        }
    }

    if (eth.get().ifIdx > 0)
    {
        // We need to forcibly delete the interface as systemd does not
        eth.get().manager.get().addReloadPostHook([idx = eth.get().ifIdx]() {
            system::deleteIntf(idx);
        });

        eth.get().manager.get().addReloadPostHook([parentIfName]() {
            execute("/bin/systemctl", "systemctl", "restart",
                    fmt::format("phosphor-ipmi-net@{}.service", parentIfName)
                        .c_str());
        });

        // Ignore the interface so the reload doesn't re-query it
        eth.get().manager.get().ignoredIntf.emplace(eth.get().ifIdx);
    }

    eth.get().manager.get().reloadConfigs();
}

nlohmann::json EthernetInterface::readJsonFile(const std::string& configFile)
{
    std::ifstream jsonFile(configFile);
    if (!jsonFile.good())
    {
        log<level::ERR>("JSON file not found");
        return nullptr;
    }

    nlohmann::json data = nullptr;
    try
    {
        data = nlohmann::json::parse(jsonFile, nullptr, false);
    }
    catch (nlohmann::json::parse_error& e)
    {
        log<level::DEBUG>("Corrupted channel config.",
                          entry("MSG: %s", e.what()));
        throw std::runtime_error("Corrupted channel config file");
    }

    return data;
}

int EthernetInterface::writeJsonFile(const std::string& configFile,
                                     const nlohmann::json& jsonData)
{
    std::ofstream jsonFile(configFile);
    if (!jsonFile.good())
    {
        log<level::ERR>("JSON file open failed",
                        entry("FILE=%s", networkChannelCfgFile));
        return -1;
    }

    // Write JSON to file
    jsonFile << jsonData;

    jsonFile.flush();
    return 0;
}

std::string EthernetInterface::getChannelPrivilege(
    const std::string& interfaceName)
{
    std::string priv(defaultChannelPriv);
    std::string retPriv;

    nlohmann::json jsonData = readJsonFile(networkChannelCfgFile);
    if (jsonData != nullptr)
    {
        try
        {
            priv = jsonData[interfaceName].get<std::string>();
            retPriv = ChannelAccessIntf::maxPrivilege(std::move(priv));
            return retPriv;
        }
        catch (const nlohmann::json::exception& e)
        {
            jsonData[interfaceName] = priv;
        }
    }
    else
    {
        jsonData[interfaceName] = priv;
    }

    if (writeJsonFile(networkChannelCfgFile, jsonData) != 0)
    {
        log<level::DEBUG>("Error in write JSON data to file",
                          entry("FILE=%s", networkChannelCfgFile));
        elog<InternalFailure>();
    }

    retPriv = ChannelAccessIntf::maxPrivilege(std::move(priv));

    return retPriv;
}

std::string EthernetInterface::maxPrivilege(std::string priv)
{
    std::string intfName = interfaceName();

    if (manager.get().supportedPrivList.empty())
    {
        // Populate the supported privilege list
        manager.get().initSupportedPrivilges();
    }

    if (!priv.empty() &&
        (std::find(manager.get().supportedPrivList.begin(),
                   manager.get().supportedPrivList.end(), priv) ==
         manager.get().supportedPrivList.end()))
    {
        log<level::ERR>("Invalid privilege");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Privilege"),
                              Argument::ARGUMENT_VALUE(priv.c_str()));
    }

    if (ChannelAccessIntf::maxPrivilege() == priv)
    {
        // No change in privilege so just return.
        return priv;
    }

    nlohmann::json jsonData = readJsonFile(networkChannelCfgFile);
    jsonData[intfName] = priv;

    if (writeJsonFile(networkChannelCfgFile, jsonData) != 0)
    {
        log<level::DEBUG>("Error in write JSON data to file",
                          entry("FILE=%s", networkChannelCfgFile));
        elog<InternalFailure>();
    }

    // Property change signal will be sent
    return ChannelAccessIntf::maxPrivilege(std::move(priv));
}

void EthernetInterface::reloadConfigs()
{
    manager.get().reloadConfigs();
}

/** @brief load the ARP Control Configurations.
 */
void EthernetInterface::loadARPControl()
{
    fs::path confPath = manager.get().getARPConfDir();
    std::string fileName = phosphor::network::arpPrefix + interfaceName() +
                           phosphor::network::arpSurffix;
    confPath /= fileName;
    config::Parser parser(confPath.string());

    auto garpEnable = getArpGarpEnabled(parser, "GARP");
    auto arpEnable = getArpEnabled(parser, "ARP_Response");
    auto garpInt = getGarpInterval(parser);
    ARPControlIface::arpResponse(arpEnable);
    ARPControlIface::gratuitousARP(garpEnable);
    ARPControlIface::gratuitousARPInterval(
        strtoul(garpInt.c_str(), nullptr, 10));

    auto cmd = ((!arpEnable) ? arpResponseDisable : arpResponseEnable) +
               sysctlConfigPrefix + interfaceName() + sysctlConfigSurffix;

    this->sysctlConfig(cmd);
}

/** @brief set the Enable/Disable of ARP Response.
 *  @param[in] value - Enable/Disable.
 *  @return the status of ARP Response
 */
bool EthernetInterface::arpResponse(bool value)
{
    auto val = ARPControlIface::arpResponse();
    if (val == value)
    {
        return val;
    }

    val = ARPControlIface::arpResponse(value);
    writeConfiguration();
    auto cmd = ((!val) ? arpResponseDisable : arpResponseEnable) +
               sysctlConfigPrefix + interfaceName() + sysctlConfigSurffix;

    this->sysctlConfig(cmd);

    return val;
}

/** @brief set the Enable/Disable of GratuitousARP.
 *  @param[in] value - Enable/Disable.
 *  @return the status of GratuitousARP Broadcasting
 */
bool EthernetInterface::gratuitousARP(bool value)
{
    auto val = ARPControlIface::gratuitousARP();
    if (val == value)
    {
        return val;
    }

    val = ARPControlIface::gratuitousARP(value);
    writeConfiguration();
    manager.get().reloadConfigs();

    return val;
}

/** @brief set the gratuitousARP interval.
 *  @param[in] interval - interval in milliseconds.
 */
uint64_t EthernetInterface::gratuitousARPInterval(uint64_t interval)
{
    auto garpInterval = ARPControlIface::gratuitousARPInterval();
    if (garpInterval == interval)
    {
        return garpInterval;
    }

    garpInterval = ARPControlIface::gratuitousARPInterval(interval);
    writeConfiguration();
    manager.get().reloadConfigs();

    return garpInterval;
}

/** Set value of LinkLocalAutoConf */
EthernetInterface::LinkLocalConf EthernetInterface::linkLocalAutoConf(
    LinkLocalConf value)
{
    if (value == EthernetInterface::linkLocalAutoConf())
    {
        return value;
    }

    EthernetInterfaceIntf::linkLocalAutoConf(value);
    manager.get().reloadConfigs();
    return value;
}

/** Set value of IPv6Enable */
bool EthernetInterface::ipv6Enable(bool value)
{
    if (value == EthernetInterfaceIntf::ipv6Enable())
    {
        log<level::INFO>("Pv6Enable no change\n");
        return value;
    }

    if (value)
    {
	if (EthernetInterfaceIntf::ipv6Enable() == false && preDhcp6State)
        {
            EthernetInterfaceIntf::dhcp6(true);
        }
        EthernetInterfaceIntf::ipv6AcceptRA(true);
        std::system(
            fmt::format("ip link set dev {} down", interfaceName()).c_str());
        std::this_thread::sleep_for(std::chrono::seconds(3));
        std::system(
            fmt::format("ip link set dev {} up", interfaceName()).c_str());
        EthernetInterfaceIntf::ipv6Enable(value);
	writeConfigurationFile();
        manager.get().reloadConfigs();
    }
    else
    {
	auto intf_count = 0;
        for (const auto& [_, intf] : manager.get().interfaces)
        {
            if (intf->EthernetInterfaceIntf::linkUp())
            {
                intf_count++;
            }
        }
        if(intf_count == 1)
        {
            if(!EthernetInterfaceIntf::ipv4Enable()){
                log<level::ERR>(
                    fmt::format(
                    "Not support in current state. IPv4 of {} is not enabled. Either enable IPv4/IPv6\n",
                     interfaceName())
                     .c_str());
                elog<NotAllowed>(NotAllowedArgument::REASON(
                     fmt::format(
                     "Not support in current state. IPv4 of {} is not enabled.\n",
                     interfaceName())
                     .c_str()));
            }
        }
	preDhcp6State = EthernetInterfaceIntf::dhcp6();
        if(dhcp6())
	{
            manager.get().addReloadPostHook([&]() {
                lg2::info("Flush IPv6 address on dev {NAME}\n", "NAME",
                          interfaceName());
                std::system(fmt::format("ip -6 addr flush dev {}", interfaceName())
                                .c_str());
            });
        }
	else
	{
            std::this_thread::sleep_for(std::chrono::seconds(10));
            lg2::info("Flush IPv6 address on dev {NAME}\n", "NAME",
                      interfaceName());
            std::system(fmt::format("ip -6 addr flush dev {}", interfaceName())
                            .c_str());
	}
        EthernetInterfaceIntf::dhcp6(false);
        EthernetInterfaceIntf::ipv6Enable(value);
	writeConfigurationFile();
        manager.get().reloadConfigs();
    }

    return value;
}

/** Set value of IPv4Enable */
bool EthernetInterface::ipv4Enable(bool value)
{
    if (value == EthernetInterfaceIntf::ipv4Enable())
    {
        log<level::INFO>("IPv4Enable no change\n");
        return value;
    }

    if (value)
    {
	if (EthernetInterfaceIntf::ipv4Enable() == false && preDhcp4State)
        {
            EthernetInterfaceIntf::dhcp4(true);
        }

        EthernetInterfaceIntf::ipv4Enable(value);
        writeConfigurationFile();
        manager.get().addReloadPostHook([ifname = interfaceName()]() {
            std::system(fmt::format("ip link set dev {} down", ifname).c_str());
            std::this_thread::sleep_for(std::chrono::seconds(3));
            std::system(fmt::format("ip link set dev {} up", ifname).c_str());
        });

        manager.get().reloadConfigs();
    }
    else
    {
	auto intf_count = 0;
        for (const auto& [_, intf] : manager.get().interfaces)
        {
            if (intf->EthernetInterfaceIntf::linkUp())
            {
                intf_count++;
            }
        }
        if(intf_count == 1)
        {
            if(!EthernetInterfaceIntf::ipv6Enable()){
                log<level::ERR>(
                    fmt::format(
                    "Not support in current state. IPv6 of {} is not enabled. Either enable IPv4/IPv6\n",
                     interfaceName())
                     .c_str());
                elog<NotAllowed>(NotAllowedArgument::REASON(
                     fmt::format(
                     "Not support in current state. IPv6 of {} is not enabled.\n",
                     interfaceName())
                     .c_str()));
            }
        }
	std::this_thread::sleep_for(std::chrono::seconds(10));
	preDhcp4State = EthernetInterfaceIntf::dhcp4();
        if(dhcp4()){
            manager.get().addReloadPostHook([&]() {
                lg2::info("Flush IPv4 address on dev {NAME}\n", "NAME",
                          interfaceName());
                std::system(fmt::format("ip -4 addr flush dev {}", interfaceName())
                                .c_str());
            });
        }
        else{
            std::this_thread::sleep_for(std::chrono::seconds(10));
            lg2::info("Flush IPv4 address on dev {NAME}\n", "NAME",
                      interfaceName());
            std::system(fmt::format("ip -4 addr flush dev {}", interfaceName())
                            .c_str());
        }
        EthernetInterfaceIntf::dhcp4(false);
        EthernetInterfaceIntf::ipv4Enable(value);
	writeConfigurationFile();
        manager.get().reloadConfigs();
    }
    return value;
}

/** Set value of IPv6EnableStaticRtr */
bool EthernetInterface::ipv6EnableStaticRtr(bool value)
{
    if (value == EthernetInterfaceIntf::ipv6EnableStaticRtr())
    {
        log<level::INFO>("IPv6EnableStaticRtr no change\n");
        return value;
    }

    if (value == false)
    {
        EthernetInterfaceIntf::ipv6StaticRtrAddr({});
        EthernetInterfaceIntf::ipv6StaticRtr2Addr({});
    }

    EthernetInterfaceIntf::ipv6EnableStaticRtr(value);
    writeConfigurationFile();
    manager.get().reloadConfigs();

    return value;
}

/** Set value of IPv6StaticRtrAddr */
std::string EthernetInterface::ipv6StaticRtrAddr(std::string value)
{
    if (value == EthernetInterfaceIntf::ipv6StaticRtrAddr())
    {
        log<level::INFO>("ipv6StaticRtrAddr no change\n");
        return value;
    }

    EthernetInterfaceIntf::ipv6StaticRtrAddr(value);
    writeConfigurationFile();
    manager.get().reloadConfigs();

    return value;
}

/** Set value of IPv6StaticRtr2Addr */
std::string EthernetInterface::ipv6StaticRtr2Addr(std::string value)
{
    if (value == EthernetInterfaceIntf::ipv6StaticRtr2Addr())
    {
        log<level::INFO>("ipv6StaticRtr2Addr no change\n");
        return value;
    }

    EthernetInterfaceIntf::ipv6StaticRtr2Addr(value);
    writeConfigurationFile();
    manager.get().reloadConfigs();

    return value;
}

/** @brief write the ARPControl configuration into the conf file.
 */
void EthernetInterface::writeConfiguration()
{
    /* write all the ARPControl configuration in the garp conf file */
    fs::path confPath = manager.get().getARPConfDir();
    std::string fileName = phosphor::network::arpPrefix + interfaceName() +
                           phosphor::network::arpSurffix;
    confPath /= fileName;
    std::fstream stream;

    stream.open(confPath.c_str(), std::fstream::out);
    if (!stream.is_open())
    {
        log<level::ERR>("Unable to open the file",
                        entry("FILE=%s", confPath.c_str()));
        elog<InternalFailure>();
    }

    config::Parser config;
    std::string garpIntv;
    garpIntv = std::to_string(ARPControlIface::gratuitousARPInterval());

    auto& Garp = config.map["GARP"].emplace_back();
    Garp["Interval"].emplace_back(garpIntv);
    Garp["Enabled"].emplace_back(
        (ARPControlIface::gratuitousARP()) ? "true" : "false");

    auto& ARPResp = config.map["ARP_Response"].emplace_back();
    ARPResp["Enabled"].emplace_back(
        (ARPControlIface::arpResponse()) ? "true" : "false");
    config.writeFile(confPath.string());

    manager.get().addReloadPostHook([]() {
        execute("/bin/systemctl", "systemctl", "restart", garpControlService);
        std::this_thread::sleep_for(std::chrono::seconds(1));
        execute("/bin/systemctl", "systemctl", "reset-failed",
                garpControlService);
    });
}

/** @brief set the ARP Response status in sysctl config for the ethernet
 * interface.
 *  @param[in] cmd - shell command.
 *  @return status of the shell command execution
 */
bool EthernetInterface::sysctlConfig(const std::string& cmd)
{
    auto pPipe = ::popen(cmd.c_str(), "r");
    if (pPipe == nullptr)
    {
        return false;
    }

    std::array<char, 256> buffer;
    std::string outConfig = "";
    while (not std::feof(pPipe))
    {
        auto bytes = std::fread(buffer.data(), 1, buffer.size(), pPipe);
        outConfig.append(buffer.data(), bytes);
    }
    ::pclose(pPipe);

    return ((outConfig.empty()) ? 1 : 0);
}

int EthernetInterface::getCreatedVLANNum(fs::path confFile)
{
    config::Parser config(confFile);
    return (config.map.getValueStrings("Network", "VLAN")).size();
}

int16_t EthernetInterface::setPHYConfiguration(bool autoNeg, Duplex duplex,
                                               uint32_t speed)
{
#if PHY_CONFIGURATION_SUPPORT
    if (this->vlan.has_value())
    {
        log<level::ERR>(
            "Not allow changing PHY configuration directly in VLAN interface.\n");
        return -1;
    }

    if (!autoNeg && speed != 10 && speed != 100)
    {
        log<level::ERR>(
            "Only Support 10 Mbps and 100 Mbps when Auto Negotiation is off");
        return -1;
    }

    if (EthernetInterfaceIntf::autoNeg() == autoNeg &&
        EthernetInterfaceIntf::duplex() == duplex &&
        EthernetInterfaceIntf::speed() == speed)
    {
        log<level::ERR>("Remain the same settings.");
        return 0;
    }

    try
    {
        unsigned char negotiation = static_cast<unsigned char>(autoNeg);
        system::setLink(
            interfaceName(), negotiation == 1 ? 1000 : speed,
            negotiation == 1 ? 1 : static_cast<unsigned char>(duplex),
            static_cast<unsigned char>(autoNeg));
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(
            fmt::format(
                "Unable to set speed/duplex with this value: {}Mbps/{}\n",
                speed,
                static_cast<unsigned char>(duplex) == 1 ? "Full" : "Half")
                .c_str());
        return -1;
    }

    EthernetInterfaceIntf::speed(speed);
    EthernetInterfaceIntf::autoNeg(autoNeg);
    EthernetInterfaceIntf::duplex(duplex);
    writeConfigurationFile();
    return 0;
#else
    log<level::ERR>("PHY Configuration feature is not enabled..\n");
    elog<UnsupportedRequest>(
        Unsupported::REASON("PHY Configuration feature is not enabled..\n"));
#endif
}

bool EthernetInterface::linkUp() const
{
    bool linkUp{};
    linkUp = EthernetInterfaceIntf::linkUp();

#ifdef AMI_NCSI_SUPPORT
    if (std::string{DEFAULT_NCSI_INTERFACE}.find(interfaceName()) !=
        std::string::npos)
        linkUp = phosphor::network::ncsi::getLinkStatus(ifIdx);
#endif

    return linkUp;
}

uint32_t EthernetInterface::speed() const
{
    auto ethInfo = ignoreError("GetEthInfo", this->interfaceName(), {}, [&] {
        return system::getEthInfo(this->interfaceName());
    });

    return ethInfo.speed;
}

EthernetInterface::Duplex EthernetInterface::duplex() const
{
    auto ethInfo = ignoreError("GetEthInfo", this->interfaceName(), {}, [&] {
        return system::getEthInfo(this->interfaceName());
    });

    return ethInfo.duplex == 1 ? Duplex::full : Duplex::half;
}

std::tuple<std::optional<std::string>, uint8_t>
    EthernetInterface::getDwMacAddrByIP(std::string gateway)
{
    int ret = 0;
    std::tuple<std::optional<std::string>, uint8_t> retVal(std::nullopt, 0);
    std::ifstream ifs("/proc/net/arp");
    if (!ifs)
    {
        log<level::INFO>("/proc/net/arp not opened\n");
        return retVal;
    }

    auto prefixLength = 0;
    for (auto& addr : addrs)
    {
        if (addr.second->type() == IP::Protocol::IPv4 &&
            addr.second->origin() != IP::AddressOrigin::LinkLocal)
        {
            prefixLength = addr.second->prefixLength();
        }
    }
    std::string line, mac;
    std::vector<std::string> vv;
    while (!ifs.eof())
    {
        ifs >> line;
        if (line == gateway)
        {
            ifs >> line >> line >> mac >> line >> line;
            if (line == interfaceName() && ether_aton(mac.c_str()) != nullptr)
            {
                std::get<0>(retVal) = mac;
                std::get<1>(retVal) = prefixLength;
                return retVal;
            }
        }
    }

    int s = -1;

    struct ifreq ifr;
    struct sockaddr_ll srcsock, dstsock, recvsock;
    int retry = 2;
    uint8_t buf[256] = {0};
    uint8_t packet[4096] = {0};
    uint8_t preMAC[6] = {0};
    struct arphdr* arph = NULL;
    socklen_t alen;
    fd_set rfds;
    struct timeval tv;
    int retval = 0;
    int nfds = 0;
    uint8_t* p = NULL;

    s = socket(PF_PACKET, SOCK_DGRAM, 0);
    if (s < 0)
    {
        goto end;
    }

    memset(&ifr, 0, sizeof(ifr));
    ret = snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s",
                   interfaceName().c_str());
    if (ret < 0 || ret >= (signed int)sizeof(ifr.ifr_name))
    {
        lg2::error("Buffer Overflow\n");
        goto close;
    }

    if (ioctl(s, SIOCGIFINDEX, &ifr) < 0)
    {
        lg2::error("Interface {INTERFACENAME} not found\n", "INTERFACENAME",
                   interfaceName());
        goto close;
    }

    srcsock.sll_family = AF_PACKET;
    srcsock.sll_ifindex = if_nametoindex(interfaceName().c_str());
    srcsock.sll_protocol = htons(ETH_P_ARP);
    if (bind(s, (struct sockaddr*)&srcsock, sizeof(srcsock)) == -1)
    {
        lg2::error(
            "Failure in Binding Interface {INTERFACENAME}'s index = {INDEX}\n",
            "INTERFACENAME", interfaceName(), "INDEX", srcsock.sll_ifindex);
        goto close;
    }

    alen = sizeof(srcsock);
    if (getsockname(s, (struct sockaddr*)&srcsock, &alen))
    {
        lg2::error("Failure in getsockname\n");
        goto close;
    }

    if (srcsock.sll_halen == 0)
    {
        log<level::ERR>(fmt::format("Interface {} is not able to communicate\n",
                                    interfaceName())
                            .c_str());
        lg2::error("Interface {INTERFACENAME} is not able to communicate\n",
                   "INTERFACENAME", interfaceName());
        goto close;
    }

    for (auto& addr : addrs)
    {
        if (addr.second->type() == IP::Protocol::IPv4 &&
            addr.second->origin() != IP::AddressOrigin::LinkLocal)
        {
            prefixLength = addr.second->prefixLength();
            retry = 2;
            while (retry)
            {
                dstsock = srcsock;
                memset(dstsock.sll_addr, -1, dstsock.sll_halen);
                in_addr addrTmp =
                    stdplus::fromStr<stdplus::In4Addr>(addr.second->address());
                uint8_t* ip = (uint8_t*)&addrTmp.s_addr;
                ip = (uint8_t*)(&addrTmp.s_addr);
                memset(buf, 0, sizeof(buf));
                memset(packet, 0, sizeof(packet));

                arph = (struct arphdr*)buf;
                p = (uint8_t*)(arph + 1);

                arph->ar_hrd = htons(ARPHRD_ETHER);
                arph->ar_pro = htons(ETH_P_IP);
                arph->ar_hln = srcsock.sll_halen;
                arph->ar_pln = 4;
                arph->ar_op = htons(ARPOP_REQUEST);
                memcpy(p, &srcsock.sll_addr, arph->ar_hln);
                p += arph->ar_hln;

                memcpy(p, &ip[0], arph->ar_pln);
                p += arph->ar_pln;

                memcpy(p, &dstsock.sll_addr, arph->ar_hln);
                p += arph->ar_hln;

                addrTmp = stdplus::fromStr<stdplus::In4Addr>(gateway);
                ip = (uint8_t*)(&addrTmp.s_addr);
                memcpy(p, &ip[0], arph->ar_pln);
                p += arph->ar_pln;

                if (0 == sendto(s, buf, p - buf, 0, (struct sockaddr*)&dstsock,
                                sizeof(dstsock)))
                {
                    continue;
                }

                arph = (struct arphdr*)packet;
                p = (unsigned char*)(arph + 1);

                FD_ZERO(&rfds);
                FD_SET(s, &rfds);
                tv.tv_sec = 2;
                tv.tv_usec = 0;
                nfds = s + 1;
                retval = select(nfds, &rfds, NULL, NULL, &tv);
                if (retval == -1)
                    lg2::error("select() error\n");
                else if (retval)
                {
                    if (FD_ISSET(s, &rfds))
                    {
                        if (recvfrom(s, packet, sizeof(packet), 0,
                                     (struct sockaddr*)&recvsock, &alen) < 0)
                        {
                            lg2::error("Failed in Recvfrom\n");
                        }
                        // If IpAddr and the ip from response are not the same,
                        // then set MAC address all zero
                        if (ip[0] != p[6] || ip[1] != p[7] || ip[2] != p[8] ||
                            ip[3] != p[9])
                        {
                            memset(p, 0, 6);
                        }
                    }
                }
                else
                {
                    goto close;
                }
                if (retry == 2)
                {
                    memcpy(preMAC, p, 6);
                }
                retry--;
            }
            if (0 == memcmp(p, preMAC, 6))
            {
                mac = fmt::format(
                    "{:0>2x}:{:0>2x}:{:0>2x}:{:0>2x}:{:0>2x}:{:0>2x}", p[0],
                    p[1], p[2], p[3], p[4], p[5]);
                std::get<0>(retVal) = mac;
                std::get<1>(retVal) = prefixLength;
                goto close;
            } // if
        }
    }

close:
    close(s);
end:
    return retVal;
}

template <sdbusplus::common::xyz::openbmc_project::network::IP::Protocol family>
int EthernetInterface::getProperIpIdx(
    std::vector<std::optional<std::string>>& list, stdplus::InAnyAddr addr)
{
    auto delimeter = ":";
    int idx = 0;
    int minIdx = IPV6_MAX_NUM;
    int MAX_NUM = IPV6_MAX_NUM;
    if (IP::Protocol::IPv4 == family)
    {
        delimeter = ".";
        minIdx = IPV4_MAX_NUM;
        MAX_NUM = IPV4_MAX_NUM;
    } // if

    auto tmpAddr = stdplus::toStr(addr);
    if (tmpAddr.find(delimeter) != std::string::npos)
    {
        for (int i = 0; i < MAX_NUM; i++)
        {
            if (list.size() > i && !list.at(i).has_value() && minIdx == MAX_NUM)
            {
                minIdx = i;
            } // if
            if (list.size() > i && list.at(i).has_value() &&
                list.at(i).value() == tmpAddr)
            {
                idx = i;
                break;
            } // if
        } // for

        if (idx == 0 && minIdx == 0)
        {
            idx = 0;
        } // if
        else if (minIdx != MAX_NUM && idx == 0)
        {
            idx = minIdx;
        } // else if
    }

    return idx;
}

std::map<std::string, std::unique_ptr<sdbusplus::bus::match_t>>
    EthernetInterface::initSignals()
{
    std::map<std::string, std::unique_ptr<sdbusplus::bus::match_t>> mp;
#if 0
    mp["DHCPSignal"] = nullptr;
#endif
    mp["ResolvdSignal"] = nullptr;
    mp["LinkSignal"] = nullptr;
    return mp;
}

ServerList EthernetInterface::getDomainNamesFromResolvd()
{
    ServerList DomainNames;
    auto OBJ_PATH = fmt::format("{}{}", RESOLVED_SERVICE_PATH, ifIdx);

    using type = std::vector<std::tuple<std::string, bool>>;
    std::variant<type> name; // Variable to capture the DNS property
    auto method = bus.get().new_method_call(RESOLVED_SERVICE, OBJ_PATH.c_str(),
                                            PROPERTY_INTERFACE, METHOD_GET);
    method.append(RESOLVED_INTERFACE, "Domains");

    try
    {
        auto reply = bus.get().call(method);
        reply.read(name);
    }
    catch (const sdbusplus::exception_t& e)
    {
        log<level::ERR>("Failed to get DNS information from Systemd-Resolved");
    }
    auto tupleVector = std::get_if<type>(&name);
    for (auto i = tupleVector->begin(); i != tupleVector->end(); ++i)
    {
        auto [domainName, fromRoute] = (*i);
        DomainNames.push_back(domainName);
    }

    return DomainNames;
}

void EthernetInterface::registerSignal(sdbusplus::bus::bus& bus)
{
    for (auto& signal : signals)
    {
        if (signal.second == nullptr && signal.first == "DHCPSignal")
        {
            signal.second = std::make_unique<sdbusplus::bus::match_t>(
                bus,
                sdbusplus::bus::match::rules::propertiesChanged(
                    DHCP_SERVICE_PATH, DHCP_PROP_INTERFACE),
                [&](sdbusplus::message::message& msg) {
                    std::map<std::string, std::variant<bool>> props;
                    std::string iface;
                    bool value;
                    msg.read(iface, props);
                    for (const auto& t : props)
                    {
                        if (t.first == "DNSEnabled")
                        {
                            value = std::get<bool>(t.second);
                            if (value)
                            {
                                EthernetInterfaceIntf::domainName({});
                            }
                        }
                    }
                });
        }
        else if (signal.second == nullptr && signal.first == "ResolvdSignal")
        {
            signal.second = std::make_unique<sdbusplus::bus::match_t>(
                bus,
                sdbusplus::bus::match::rules::propertiesChanged(
                    RESOLVD_OBJ_PATH, RESOLVD_MANAGER_INTERFACE),
                [&](sdbusplus::message::message& msg) {
                    std::map<
                        std::string,
                        std::variant<
                            std::vector<std::tuple<int, std::string, bool>>,
                            std::vector<
                                std::tuple<int, int, std::vector<uint8_t>>>>>
                        props;
                    std::string iface;
                    std::vector<std::tuple<std::string, bool>> value;
                    msg.read(iface, props);
                    for (const auto& t : props)
                    {
                        auto vector = getDomainNamesFromResolvd();
                        EthernetInterfaceIntf::domainName(
                            getDomainNamesFromResolvd());
                    }
                });
        }
        else if (signal.second == nullptr && signal.first == "LinkSignal")
        {
            signal.second = std::make_unique<sdbusplus::bus::match_t>(
                bus,
                sdbusplus::bus::match::rules::propertiesChanged(
                    fmt::format("{}_3{}", NETWORKD_LINK_PATH_PREFIX,
                                std::to_string(ifIdx))
                        .c_str(),
                    NETWORKD_LINK_INTERFACE),
                [&](sdbusplus::message::message& msg) {
                    std::map<std::string,
                             std::variant<std::string,
                                          std::tuple<uint64_t, uint64_t>>>
                        props;
                    std::string iface;
                    std::vector<std::tuple<std::string, bool>> value;
                    msg.read(iface, props);
                    for (const auto& t : props)
                    {
                        if (t.first == "IPv6AddressState")
                        {
                            if (std::get<std::string>(t.second) == "routable" &&
                                dhcp6())
                            {
                                // std::this_thread::sleep_for(std::chrono::seconds(5));
                                auto lists =
                                    manager.get().getGateway6FromFile();
                                for (auto line : lists)
                                {
                                    std::stringstream ss(line);
                                    std::string dstIP, dstPrefix, srcIP,
                                        srcPrefix, nextHop, metric, count,
                                        useCount, devName, flags;
                                    ss >> dstIP >> dstPrefix >> srcIP >>
                                        srcPrefix >> nextHop >> flags >>
                                        metric >> count >> useCount >> devName;
                                    if (devName.compare(interfaceName()) != 0)
                                        continue;
                                    int flagInt = std::stoul(flags, 0, 16);
                                    if (((flagInt & 0x400) == 0x400) &&
                                        nextHop.compare(
                                            "00000000000000000000000000000000") !=
                                            0)
                                    {
                                        for (int i = 4; i < nextHop.size();
                                             i = i + 4)
                                        {
                                            nextHop.insert(i, ":");
                                            i++;
                                        }
                                        in6_addr addr;
                                        char buf[INET6_ADDRSTRLEN] = {0};
                                        inet_pton(AF_INET6, nextHop.c_str(),
                                                  &addr);
                                        inet_ntop(AF_INET6, &addr, buf,
                                                  INET6_ADDRSTRLEN);
                                        EthernetInterfaceIntf::defaultGateway6(
                                            std::string{buf}, true);
                                        break;
                                    }
                                }
                            }
                        }
                        else if (t.first == "IPv4AddressState")
                        {
                            if (std::get<std::string>(t.second) == "routable" &&
                                dhcp4())
                            {
                                // std::this_thread::sleep_for(std::chrono::seconds(5));
                                auto lists = manager.get().getGatewayFromFile();
                                for (auto line : lists)
                                {
                                    std::stringstream ss(line);
                                    std::string Iface, dst, gateway, flags, cnt,
                                        use, metric, mask, mtu, window, irtt;
                                    ss >> Iface >> dst >> gateway >> flags >>
                                        cnt >> use >> metric >> mask >> mtu >>
                                        window >> irtt;
                                    if (Iface.compare(interfaceName()) != 0)
                                        continue;
                                    int flagInt = std::stoul(flags, 0, 16);
                                    if (((flagInt & 0x2) == 0x2) &&
                                        gateway.compare("00000000") != 0)
                                    {
                                        auto gwInt = std::stoul(gateway, 0, 16);
                                        auto gwStr = fmt::format(
                                            "{}.{}.{}.{}", (gwInt & 0x000000FF),
                                            (gwInt & 0x0000FF00) >> 8,
                                            (gwInt & 0x00FF0000) >> 16,
                                            (gwInt & 0xFF000000) >> 24);
                                        EthernetInterfaceIntf::defaultGateway(
                                            std::string{gwStr}, true);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                });
        }
    }
}

std::vector<RACFG_T> EthernetInterface::getIPv6DynamicRouterInfo()
{
    try
    {
        RACFG_T racfg;
        std::vector<RACFG_T> Vec;

        auto dynamicGateway =
            std::make_unique<racfg6::route>(interfaceName().c_str());

        const auto& rInfo = dynamicGateway->getIPv6DynamicRouterInfo();

        for (auto str = rInfo.begin(); str != rInfo.end(); str++)
        {
            std::get<0>(racfg) = std::vector<uint8_t>(
                str->gateway6, str->gateway6 + sizeof(str->gateway6));
            std::get<1>(racfg) = std::vector<uint8_t>(
                str->prefix, str->prefix + sizeof(str->prefix));
            std::get<2>(racfg) = str->prefixlen;
            std::get<3>(racfg) = std::vector<uint8_t>(
                str->gateway6MAC, str->gateway6MAC + sizeof(str->gateway6MAC));

            Vec.push_back(racfg);
        }
        return Vec;
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed with exception : {ERROR}", "ERROR", e);
    }
}

std::string EthernetInterface::dhcpv6DUID() const
{
    try
    {
        std::string res = "";
        std::string filename = "/var/run/systemd/netif/links/";
        std::string delim = "DHCP6_CLIENT_DUID=DUID-LL:";

        filename += std::to_string(ifIdx);
        std::ifstream infile;
        infile.open(filename.c_str(), std::ios::in);
        if (infile.is_open())
        {
            std::string line;
            while (infile.good())
            {
                std::getline(infile, line);
                size_t pos = line.find(delim);
                if (pos == std::string::npos)
                {
                    line.clear();
                    continue;
                }
                else
                {
                    res = line.substr(pos + delim.length(), std::string::npos);
                    break;
                }
            }
            infile.close();
        }
        return res;
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed with exception : {ERROR}", "ERROR", e);
    }
}

std::vector<uint8_t> EthernetInterface::dhcpv6TimingParamReadIfaceFile(
    const config::Parser& config)
{
    std::vector<uint8_t> val;
    std::string_view Section = "DHCPv6TimingConf";

    const std::string* value;
    value = config.map.getLastValueString(Section, "SOLMaxDelay");
    if (value == nullptr)
    {
        val.push_back(DHCPv6TimingParamDefault::SOLMaxDelay);
    }
    else
    {
        val.push_back(static_cast<uint8_t>(std::stoul(*value, nullptr, 10)));
    }

    value = config.map.getLastValueString(Section, "SOLTimeout");
    if (value == nullptr)
    {
        val.push_back(DHCPv6TimingParamDefault::SOLTimeout);
    }
    else
    {
        val.push_back(static_cast<uint8_t>(std::stoul(*value, nullptr, 10)));
    }

    value = config.map.getLastValueString(Section, "SOLMaxRt");
    if (value == nullptr)
    {
        val.push_back(DHCPv6TimingParamDefault::SOLMaxRt);
    }
    else
    {
        val.push_back(static_cast<uint8_t>(std::stoul(*value, nullptr, 10)));
    }

    value = config.map.getLastValueString(Section, "REQTimeout");
    if (value == nullptr)
    {
        val.push_back(DHCPv6TimingParamDefault::REQTimeout);
    }
    else
    {
        val.push_back(static_cast<uint8_t>(std::stoul(*value, nullptr, 10)));
    }

    value = config.map.getLastValueString(Section, "REQMaxRt");
    if (value == nullptr)
    {
        val.push_back(DHCPv6TimingParamDefault::REQMaxRt);
    }
    else
    {
        val.push_back(static_cast<uint8_t>(std::stoul(*value, nullptr, 10)));
    }

    value = config.map.getLastValueString(Section, "REQMaxRc");
    if (value == nullptr)
    {
        val.push_back(DHCPv6TimingParamDefault::REQMaxRc);
    }
    else
    {
        val.push_back(static_cast<uint8_t>(std::stoul(*value, nullptr, 10)));
    }

    value = config.map.getLastValueString(Section, "RENTimeout");
    if (value == nullptr)
    {
        val.push_back(DHCPv6TimingParamDefault::RENTimeout);
    }
    else
    {
        val.push_back(static_cast<uint8_t>(std::stoul(*value, nullptr, 10)));
    }

    value = config.map.getLastValueString(Section, "RENMaxRt");
    if (value == nullptr)
    {
        val.push_back(DHCPv6TimingParamDefault::RENMaxRt);
    }
    else
    {
        val.push_back(static_cast<uint8_t>(std::stoul(*value, nullptr, 10)));
    }

    value = config.map.getLastValueString(Section, "REBTimeout");
    if (value == nullptr)
    {
        val.push_back(DHCPv6TimingParamDefault::REBTimeout);
    }
    else
    {
        val.push_back(std::stoul(*value, nullptr, 10));
    }

    value = config.map.getLastValueString(Section, "REBMaxRt");
    if (value == nullptr)
    {
        val.push_back(DHCPv6TimingParamDefault::REBMaxRt);
    }
    else
    {
        val.push_back(static_cast<uint8_t>(std::stoul(*value, nullptr, 10)));
    }

    value = config.map.getLastValueString(Section, "INFTimeout");
    if (value == nullptr)
    {
        val.push_back(DHCPv6TimingParamDefault::INFTimeout);
    }
    else
    {
        val.push_back(static_cast<uint8_t>(std::stoul(*value, nullptr, 10)));
    }

    value = config.map.getLastValueString(Section, "INFMaxRt");
    if (value == nullptr)
    {
        val.push_back(DHCPv6TimingParamDefault::INFMaxRt);
    }
    else
    {
        val.push_back(static_cast<uint16_t>(std::stoul(*value, nullptr, 10)));
    }

    return val;
}

void EthernetInterface::dhcpv6TimingParamWriteConfFile(config::Parser& config)
{
    std::vector<uint8_t> value = EthernetInterfaceIntf::dhcpv6TimingConfParam();
    if (value.empty())
    {
        return;
    }
    auto it = value.begin();

    auto& dhcp6TimingConf = config.map["DHCPv6TimingConf"].emplace_back();

    float val = 0;

    if (*it != 0)
    {
        val = static_cast<float>((
            (DHCPv6_Timing_Param[2 * static_cast<int>(
                                         DHCPv6TimingParamIndex::SOLMaxDelay) +
                                 1] -
             DHCPv6_Timing_Param
                 [2 * static_cast<int>(DHCPv6TimingParamIndex::SOLMaxDelay)]) +
            (static_cast<float>(*it) *
             DHCPv6_Timing_Param
                 [2 * static_cast<int>(DHCPv6TimingParamIndex::SOLMaxDelay)])));
        dhcp6TimingConf["SOLMaxDelay"].emplace_back(fmt::format("{}", val));
    }
    it++;
    if (*it != 0)
    {
        val = static_cast<float>((
            (DHCPv6_Timing_Param[2 * static_cast<int>(
                                         DHCPv6TimingParamIndex::SOLTimeout) +
                                 1] -
             DHCPv6_Timing_Param[2 * static_cast<int>(
                                         DHCPv6TimingParamIndex::SOLTimeout)]) +
            (static_cast<float>(*it) *
             DHCPv6_Timing_Param
                 [2 * static_cast<int>(DHCPv6TimingParamIndex::SOLTimeout)])));
        dhcp6TimingConf["SOLTimeout"].emplace_back(fmt::format("{}", val));
    }
    it++;
    if (*it != 0)
    {
        val = static_cast<float>(
            ((DHCPv6_Timing_Param
                  [2 * static_cast<int>(DHCPv6TimingParamIndex::SOLMaxRt) + 1] -
              DHCPv6_Timing_Param[2 * static_cast<int>(
                                          DHCPv6TimingParamIndex::SOLMaxRt)]) +
             (static_cast<float>(*it) *
              DHCPv6_Timing_Param[2 * static_cast<int>(
                                          DHCPv6TimingParamIndex::SOLMaxRt)])));
        dhcp6TimingConf["SOLMaxRt"].emplace_back(fmt::format("{}", val));
    }
    it++;
    if (*it != 0)
    {
        val = static_cast<float>((
            (DHCPv6_Timing_Param[2 * static_cast<int>(
                                         DHCPv6TimingParamIndex::REQTimeout) +
                                 1] -
             DHCPv6_Timing_Param[2 * static_cast<int>(
                                         DHCPv6TimingParamIndex::REQTimeout)]) +
            (static_cast<float>(*it) *
             DHCPv6_Timing_Param
                 [2 * static_cast<int>(DHCPv6TimingParamIndex::REQTimeout)])));
        dhcp6TimingConf["REQTimeout"].emplace_back(fmt::format("{}", val));
    }
    it++;
    if (*it != 0)
    {
        val = static_cast<float>(
            ((DHCPv6_Timing_Param
                  [2 * static_cast<int>(DHCPv6TimingParamIndex::REQMaxRt) + 1] -
              DHCPv6_Timing_Param[2 * static_cast<int>(
                                          DHCPv6TimingParamIndex::REQMaxRt)]) +
             (static_cast<float>(*it) *
              DHCPv6_Timing_Param[2 * static_cast<int>(
                                          DHCPv6TimingParamIndex::REQMaxRt)])));
        dhcp6TimingConf["REQMaxRt"].emplace_back(fmt::format("{}", val));
    }
    it++;
    if (*it != 0)
    {
        val = static_cast<float>(
            ((DHCPv6_Timing_Param
                  [2 * static_cast<int>(DHCPv6TimingParamIndex::REQMaxRc) + 1] -
              DHCPv6_Timing_Param[2 * static_cast<int>(
                                          DHCPv6TimingParamIndex::REQMaxRc)]) +
             (static_cast<float>(*it) *
              DHCPv6_Timing_Param[2 * static_cast<int>(
                                          DHCPv6TimingParamIndex::REQMaxRc)])));
        dhcp6TimingConf["REQMaxRc"].emplace_back(fmt::format("{}", val));
    }
    it++;
    if (*it != 0)
    {
        val = static_cast<float>((
            (DHCPv6_Timing_Param[2 * static_cast<int>(
                                         DHCPv6TimingParamIndex::RENTimeout) +
                                 1] -
             DHCPv6_Timing_Param[2 * static_cast<int>(
                                         DHCPv6TimingParamIndex::RENTimeout)]) +
            (static_cast<float>(*it) *
             DHCPv6_Timing_Param
                 [2 * static_cast<int>(DHCPv6TimingParamIndex::RENTimeout)])));
        dhcp6TimingConf["RENTimeout"].emplace_back(fmt::format("{}", val));
    }
    it++;
    if (*it != 0)
    {
        val = static_cast<float>(
            ((DHCPv6_Timing_Param
                  [2 * static_cast<int>(DHCPv6TimingParamIndex::RENMaxRt) + 1] -
              DHCPv6_Timing_Param[2 * static_cast<int>(
                                          DHCPv6TimingParamIndex::RENMaxRt)]) +
             (static_cast<float>(*it) *
              DHCPv6_Timing_Param[2 * static_cast<int>(
                                          DHCPv6TimingParamIndex::RENMaxRt)])));
        dhcp6TimingConf["RENMaxRt"].emplace_back(fmt::format("{}", val));
    }
    it++;
    if (*it != 0)
    {
        val = static_cast<float>((
            (DHCPv6_Timing_Param[2 * static_cast<int>(
                                         DHCPv6TimingParamIndex::REBTimeout) +
                                 1] -
             DHCPv6_Timing_Param[2 * static_cast<int>(
                                         DHCPv6TimingParamIndex::REBTimeout)]) +
            (static_cast<float>(*it) *
             DHCPv6_Timing_Param
                 [2 * static_cast<int>(DHCPv6TimingParamIndex::REBTimeout)])));
        dhcp6TimingConf["REBTimeout"].emplace_back(fmt::format("{}", val));
    }
    it++;
    if (*it != 0)
    {
        val = static_cast<float>(
            ((DHCPv6_Timing_Param
                  [2 * static_cast<int>(DHCPv6TimingParamIndex::REBMaxRt) + 1] -
              DHCPv6_Timing_Param[2 * static_cast<int>(
                                          DHCPv6TimingParamIndex::REBMaxRt)]) +
             (static_cast<float>(*it) *
              DHCPv6_Timing_Param[2 * static_cast<int>(
                                          DHCPv6TimingParamIndex::REBMaxRt)])));
        dhcp6TimingConf["REBMaxRt"].emplace_back(fmt::format("{}", val));
    }
    it++;
    if (*it != 0)
    {
        val = static_cast<float>((
            (DHCPv6_Timing_Param[2 * static_cast<int>(
                                         DHCPv6TimingParamIndex::INFTimeout) +
                                 1] -
             DHCPv6_Timing_Param[2 * static_cast<int>(
                                         DHCPv6TimingParamIndex::INFTimeout)]) +
            (static_cast<float>(*it) *
             DHCPv6_Timing_Param
                 [2 * static_cast<int>(DHCPv6TimingParamIndex::INFTimeout)])));
        dhcp6TimingConf["INFTimeout"].emplace_back(fmt::format("{}", val));
    }
    it++;
    if (*it != 0)
    {
        val = static_cast<float>(
            ((DHCPv6_Timing_Param
                  [2 * static_cast<int>(DHCPv6TimingParamIndex::INFMaxRt) + 1] -
              DHCPv6_Timing_Param[2 * static_cast<int>(
                                          DHCPv6TimingParamIndex::INFMaxRt)]) +
             (static_cast<float>(*it) *
              DHCPv6_Timing_Param[2 * static_cast<int>(
                                          DHCPv6TimingParamIndex::INFMaxRt)])));
        dhcp6TimingConf["INFMaxRt"].emplace_back(fmt::format("{}", val));
    }
}

/** Set value of DHCPv6TimingConfParam */
std::vector<uint8_t> EthernetInterface::dhcpv6TimingConfParam(
    std::vector<uint8_t> value)
{
    if (value.size() != MAX_SUPPORTED_DHCPv6_TIMING_PARAMS)
    {
        log<level::ERR>(
            fmt::format("Provided arguments data is not 12 bytes for {}.\n",
                        interfaceName())
                .c_str());
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("size"),
            Argument::ARGUMENT_VALUE(std::to_string(value.size()).c_str()));
    }

    for (auto i : value)
    {
        if (i == 0)
        {
            log<level::ERR>(
                fmt::format(
                    "Provided arguments value zero is not allowed for index {}.\n",
                    i)
                    .c_str());
            elog<InvalidArgument>(
                Argument::ARGUMENT_NAME("size"),
                Argument::ARGUMENT_VALUE(std::to_string(value.size()).c_str()));
        }
    }
    if (value[static_cast<int>(DHCPv6TimingParamIndex::SOLMaxDelay)] > 254)
    {
        log<level::ERR>(
            fmt::format("SOLMaxDelay is above max acceptable value for {}.\n",
                        interfaceName())
                .c_str());
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("SOLMaxDelay"),
            Argument::ARGUMENT_VALUE(
                std::to_string(value[static_cast<int>(
                                   DHCPv6TimingParamIndex::SOLMaxDelay)])
                    .c_str()));
    }

    if (value[static_cast<int>(DHCPv6TimingParamIndex::SOLTimeout)] > 254)
    {
        log<level::ERR>(
            fmt::format("INFTimeout is above max acceptable value for {}.\n",
                        interfaceName())
                .c_str());
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("SOLTimeout"),
            Argument::ARGUMENT_VALUE(
                std::to_string(
                    value[static_cast<int>(DHCPv6TimingParamIndex::SOLTimeout)])
                    .c_str()));
    }

    if (value[static_cast<int>(DHCPv6TimingParamIndex::REQTimeout)] > 254)
    {
        log<level::ERR>(
            fmt::format("REQTimeout is above max acceptable value for {}.\n",
                        interfaceName())
                .c_str());
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("REQTimeout"),
            Argument::ARGUMENT_VALUE(
                std::to_string(
                    value[static_cast<int>(DHCPv6TimingParamIndex::REQTimeout)])
                    .c_str()));
    }

    if (value[static_cast<int>(DHCPv6TimingParamIndex::REQMaxRc)] > 101)
    {
        log<level::ERR>(
            fmt::format("REQMaxRc is above max acceptable value for {}.\n",
                        interfaceName())
                .c_str());
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("REQMaxRc"),
            Argument::ARGUMENT_VALUE(
                std::to_string(
                    value[static_cast<int>(DHCPv6TimingParamIndex::REQMaxRc)])
                    .c_str()));
    }

    if (value[static_cast<int>(DHCPv6TimingParamIndex::INFTimeout)] > 254)
    {
        log<level::ERR>(
            fmt::format("INFTimeout is above max acceptable value for {}.\n",
                        interfaceName())
                .c_str());
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("INFTimeout"),
            Argument::ARGUMENT_VALUE(
                std::to_string(
                    value[static_cast<int>(DHCPv6TimingParamIndex::INFTimeout)])
                    .c_str()));
    }

    value = EthernetInterfaceIntf::dhcpv6TimingConfParam(value);
    writeConfigurationFile();
    writeIfaceStateFile(interfaceName());
    manager.get().reloadConfigs();
    return value;
}

std::vector<uint8_t> EthernetInterface::slaacTimingParamReadIfaceFile(
    const config::Parser& config)
{
    std::vector<uint8_t> val;
    std::string_view Section = "SLAACTimingConf";

    const std::string* value;
    value = config.map.getLastValueString(Section, "MaxRtrSolicitationDelay");
    if (value == nullptr)
    {
        val.push_back(SLAACTimingParamDefault::MaxRtrSolicitationDelay);
    }
    else
    {
        val.push_back(static_cast<uint8_t>(std::stoul(*value, nullptr, 10)));
    }

    value = config.map.getLastValueString(Section, "RtrSolicitationInterval");
    if (value == nullptr)
    {
        val.push_back(SLAACTimingParamDefault::RtrSolicitationInterval);
    }
    else
    {
        val.push_back(static_cast<uint8_t>(std::stoul(*value, nullptr, 10)));
    }

    value = config.map.getLastValueString(Section, "MaxRtrSolicitations");
    if (value == nullptr)
    {
        val.push_back(SLAACTimingParamDefault::MaxRtrSolicitations);
    }
    else
    {
        val.push_back(static_cast<uint8_t>(std::stoul(*value, nullptr, 10)));
    }

    value = config.map.getLastValueString(Section, "DupAddrDetectTransmits");
    if (value == nullptr)
    {
        val.push_back(SLAACTimingParamDefault::DupAddrDetectTransmits);
    }
    else
    {
        val.push_back(static_cast<uint8_t>(std::stoul(*value, nullptr, 10)));
    }

    value = config.map.getLastValueString(Section, "MaxMulticastSolicit");
    if (value == nullptr)
    {
        val.push_back(SLAACTimingParamDefault::MaxMulticastSolicit);
    }
    else
    {
        val.push_back(static_cast<uint8_t>(std::stoul(*value, nullptr, 10)));
    }

    value = config.map.getLastValueString(Section, "MaxUnicastSolicit");
    if (value == nullptr)
    {
        val.push_back(SLAACTimingParamDefault::MaxUnicastSolicit);
    }
    else
    {
        val.push_back(static_cast<uint8_t>(std::stoul(*value, nullptr, 10)));
    }

    value = config.map.getLastValueString(Section, "MaxAnycastDelayTime");
    if (value == nullptr)
    {
        val.push_back(SLAACTimingParamDefault::MaxAnycastDelayTime);
    }
    else
    {
        val.push_back(static_cast<uint8_t>(std::stoul(*value, nullptr, 10)));
    }

    value = config.map.getLastValueString(Section, "MaxNeighborAdvertisement");
    if (value == nullptr)
    {
        val.push_back(SLAACTimingParamDefault::MaxNeighborAdvertisement);
    }
    else
    {
        val.push_back(static_cast<uint8_t>(std::stoul(*value, nullptr, 10)));
    }

    value = config.map.getLastValueString(Section, "ReachableTime");
    if (value == nullptr)
    {
        val.push_back(SLAACTimingParamDefault::ReachableTime);
    }
    else
    {
        val.push_back(std::stoul(*value, nullptr, 10));
    }

    value = config.map.getLastValueString(Section, "RetransTimer");
    if (value == nullptr)
    {
        val.push_back(SLAACTimingParamDefault::RetransTimer);
    }
    else
    {
        val.push_back(static_cast<uint8_t>(std::stoul(*value, nullptr, 10)));
    }

    value = config.map.getLastValueString(Section, "DelayFirstProbeTime");
    if (value == nullptr)
    {
        val.push_back(SLAACTimingParamDefault::DelayFirstProbeTime);
    }
    else
    {
        val.push_back(static_cast<uint8_t>(std::stoul(*value, nullptr, 10)));
    }

    return val;
}

static uint8_t convertSLAACTimingParamValueToActual(uint8_t value, int index)
{
    float val = 0;
    val = static_cast<float>(
        ((SLAAC_Timing_Param[(2 * index) + 1] - SLAAC_Timing_Param[2 * index]) +
         (static_cast<float>(value) * SLAAC_Timing_Param[2 * index])));

    uint32_t floatval = static_cast<uint32_t>(val);

    float fractional = val - floatval;

    if (fractional != 0.0)
    {
        val += 1;
    }

    return static_cast<uint8_t>(val);
}

/** Set value of IPv6SLAACTimingConfParam */
std::vector<uint8_t> EthernetInterface::ipv6SLAACTimingConfParam(
    std::vector<uint8_t> value)
{
    const std::string procConfLoc = "/proc/sys/net/ipv6/conf/";
    const std::string procNeighLoc = "/proc/sys/net/ipv6/neigh/";

    if (value.size() != MAX_SUPPORTED_SLAAC_TIMING_PARAMS)
    {
        log<level::ERR>(
            fmt::format("Provided arguments data is not 11 bytes for {}.\n",
                        interfaceName())
                .c_str());
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("size"),
            Argument::ARGUMENT_VALUE(std::to_string(value.size()).c_str()));
    }

    for (int i = 0; i < MAX_SUPPORTED_SLAAC_TIMING_PARAMS; i++)
    {
        if ((i == SLAACTimingParamIndex::MaxNeighborAdvertisement) ||
            (i == SLAACTimingParamIndex::DupAddrDetectTransmits))
        {
            continue;
        }
        else if (value[i] == 0)
        {
            log<level::ERR>(
                fmt::format(
                    "Provided arguments value zero is not allowed for index {}.\n",
                    i)
                    .c_str());
            elog<InvalidArgument>(
                Argument::ARGUMENT_NAME("size"),

                Argument::ARGUMENT_VALUE(std::to_string(value.size()).c_str()));
        }
    }
    if ((value[SLAACTimingParamIndex::MaxRtrSolicitations] > 100) &&
        (value[SLAACTimingParamIndex::MaxRtrSolicitations] < 255))
    {
        log<level::ERR>(
            fmt::format("Invalid value for MaxRtrSolicitations on {}.\n",
                        interfaceName())
                .c_str());
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("MaxRtrSolicitations"),
            Argument::ARGUMENT_VALUE(
                std::to_string(
                    value[SLAACTimingParamIndex::MaxRtrSolicitations])
                    .c_str()));
    }

    if (value[SLAACTimingParamIndex::DupAddrDetectTransmits] > 101)
    {
        log<level::ERR>(
            fmt::format(
                "DupAddrDetectTransmits is above max acceptable value for {}.\n",
                interfaceName())
                .c_str());
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("DupAddrDetectTransmits"),
            Argument::ARGUMENT_VALUE(
                std::to_string(
                    value[SLAACTimingParamIndex::DupAddrDetectTransmits])
                    .c_str()));
    }

    if (value[SLAACTimingParamIndex::MaxMulticastSolicit] > 100)
    {
        log<level::ERR>(
            fmt::format(
                "MaxMulticastSolicit is above max acceptable value for {}.\n",
                interfaceName())
                .c_str());
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("MaxMulticastSolicit"),
            Argument::ARGUMENT_VALUE(
                std::to_string(
                    value[SLAACTimingParamIndex::MaxMulticastSolicit])
                    .c_str()));
    }

    if (value[SLAACTimingParamIndex::MaxUnicastSolicit] > 100)
    {
        log<level::ERR>(
            fmt::format(
                "MaxUnicastSolicit is above max acceptable value for {}.\n",
                interfaceName())
                .c_str());
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("MaxUnicastSolicit"),
            Argument::ARGUMENT_VALUE(
                std::to_string(value[SLAACTimingParamIndex::MaxUnicastSolicit])
                    .c_str()));
    }

    if (value[SLAACTimingParamIndex::MaxNeighborAdvertisement] != 0)
    {
        log<level::ERR>(
            fmt::format(
                "MaxNeighborAdvertisement is not allowed to set for {}.\n",
                interfaceName())
                .c_str());
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("MaxNeighborAdvertisement"),
            Argument::ARGUMENT_VALUE(
                std::to_string(
                    value[SLAACTimingParamIndex::MaxNeighborAdvertisement])
                    .c_str()));
    }

    std::string ipv6conf;
    constexpr uint16_t toMilliSec = 1000;

    ipv6conf = procConfLoc + interfaceName().c_str() +
               "/router_solicitation_delay";

    std::system(
        fmt::format("/bin/echo {} > {}",
                    convertSLAACTimingParamValueToActual(
                        value[SLAACTimingParamIndex::MaxRtrSolicitationDelay],
                        SLAACTimingParamIndex::MaxRtrSolicitationDelay),
                    ipv6conf)
            .c_str());

    ipv6conf = procConfLoc + interfaceName().c_str() +
               "/router_solicitation_interval";

    std::system(
        fmt::format("/bin/echo {} > {}",
                    convertSLAACTimingParamValueToActual(
                        value[SLAACTimingParamIndex::RtrSolicitationInterval],
                        SLAACTimingParamIndex::RtrSolicitationInterval),
                    ipv6conf)
            .c_str());

    ipv6conf = procConfLoc + interfaceName().c_str() + "/router_solicitations";

    if (value[SLAACTimingParamIndex::MaxRtrSolicitations] == 255)
    {
        std::system(fmt::format("/bin/echo -1 > {}", ipv6conf).c_str());
    }
    else
    {
        std::system(
            fmt::format("/bin/echo {} > {}",
                        convertSLAACTimingParamValueToActual(
                            value[SLAACTimingParamIndex::MaxRtrSolicitations],
                            SLAACTimingParamIndex::MaxRtrSolicitations),
                        ipv6conf)
                .c_str());
    }

    ipv6conf = procConfLoc + interfaceName().c_str() + "/dad_transmits";

    std::system(
        fmt::format("/bin/echo {} > {}",
                    convertSLAACTimingParamValueToActual(
                        value[SLAACTimingParamIndex::DupAddrDetectTransmits],
                        SLAACTimingParamIndex::DupAddrDetectTransmits),
                    ipv6conf)
            .c_str());

    ipv6conf = procNeighLoc + interfaceName().c_str() + "/mcast_solicit";

    std::system(
        fmt::format("/bin/echo {} > {}",
                    convertSLAACTimingParamValueToActual(
                        value[SLAACTimingParamIndex::MaxMulticastSolicit],
                        SLAACTimingParamIndex::MaxMulticastSolicit),
                    ipv6conf)
            .c_str());

    ipv6conf = procNeighLoc + interfaceName().c_str() + "/ucast_solicit";

    std::system(fmt::format("/bin/echo {} > {}",
                            convertSLAACTimingParamValueToActual(
                                value[SLAACTimingParamIndex::MaxUnicastSolicit],
                                SLAACTimingParamIndex::MaxUnicastSolicit),
                            ipv6conf)
                    .c_str());

    ipv6conf = procNeighLoc + interfaceName().c_str() + "/anycast_delay";

    std::system(
        fmt::format("/bin/echo {} > {}",
                    convertSLAACTimingParamValueToActual(
                        value[SLAACTimingParamIndex::MaxAnycastDelayTime],
                        SLAACTimingParamIndex::MaxAnycastDelayTime),
                    ipv6conf)
            .c_str());

    ipv6conf = procNeighLoc + interfaceName().c_str() +
               "/base_reachable_time_ms";

    std::system(
        fmt::format(
            "/bin/echo {} > {}",
            (static_cast<uint16_t>(
                 ((SLAAC_Timing_Param
                       [(2 * SLAACTimingParamIndex::ReachableTime) + 1] -
                   SLAAC_Timing_Param[2 *
                                      SLAACTimingParamIndex::ReachableTime]) +
                  (static_cast<float>(
                       value[SLAACTimingParamIndex::ReachableTime]) *
                   SLAAC_Timing_Param[2 *
                                      SLAACTimingParamIndex::ReachableTime]))) *
             toMilliSec),
            ipv6conf)
            .c_str());

    ipv6conf = procNeighLoc + interfaceName().c_str() + "/retrans_time_ms";

    std::system(
        fmt::format(
            "/bin/echo {} > {}",
            (static_cast<float>((
                 (SLAAC_Timing_Param[(2 * SLAACTimingParamIndex::RetransTimer) +
                                     1] -
                  SLAAC_Timing_Param[2 * SLAACTimingParamIndex::RetransTimer]) +
                 (static_cast<float>(
                      value[SLAACTimingParamIndex::RetransTimer]) *
                  SLAAC_Timing_Param[2 *
                                     SLAACTimingParamIndex::RetransTimer]))) *
             toMilliSec),
            ipv6conf)
            .c_str());

    ipv6conf = procNeighLoc + interfaceName().c_str() +
               "/delay_first_probe_time";

    std::system(
        fmt::format("/bin/echo {} > {}",
                    convertSLAACTimingParamValueToActual(
                        value[SLAACTimingParamIndex::DelayFirstProbeTime],
                        SLAACTimingParamIndex::DelayFirstProbeTime),
                    ipv6conf)
            .c_str());

    value = EthernetInterfaceIntf::ipv6SLAACTimingConfParam(value);
    writeIfaceStateFile(interfaceName());
    return value;
}

/** Get Metric value of Default Gateway */
uint16_t EthernetInterface::getMetricValueDefaultGateway(std::string value)
{
    uint16_t Metric = 1024;
    auto lists = manager.get().getGatewayFromFile();
    for (auto line : lists)
    {
        std::stringstream ss(line);
        std::string Iface, dst, gateway, flags, cnt, use, metric, mask, mtu,
            window, irtt;
        ss >> Iface >> dst >> gateway >> flags >> cnt >> use >> metric >>
            mask >> mtu >> window >> irtt;
        if (Iface.compare(interfaceName()) != 0)
            continue;
        int flagInt = std::stoul(flags, 0, 16);
        if (((flagInt & 0x2) == 0x2) && (gateway.compare("00000000") != 0) &&
            (dst.compare("00000000") == 0))
        {
            auto gwInt = std::stoul(gateway, 0, 16);
            auto gwStr = fmt::format(
                "{}.{}.{}.{}", (gwInt & 0x000000FF), (gwInt & 0x0000FF00) >> 8,
                (gwInt & 0x00FF0000) >> 16, (gwInt & 0xFF000000) >> 24);
            if (gwStr.compare(EthernetInterfaceIntf::defaultGateway()) == 0)
            {
                Metric = static_cast<uint16_t>(std::stoul(metric, 0, 10));
            }
            break;
        }
    }
    return Metric;
}

/** Set value of BackupGateway */
std::string EthernetInterface::backupGateway(std::string value)
{
    if (!EthernetInterfaceIntf::ipv4Enable())
    {
        log<level::ERR>(
            fmt::format("Not support in current state. IPv4 is not enabled.\n",
                        interfaceName())
                .c_str());
        elog<NotAllowed>(NotAllowedArgument::REASON(
            fmt::format("Not support in current state. IPv4 is not enabled.\n",
                        interfaceName())
                .c_str()));
    }

    if (EthernetInterfaceIntf::dhcp4())
    {
        log<level::ERR>(
            fmt::format("Not support in current state. IPv4 Source is dhcp.\n",
                        interfaceName())
                .c_str());
        elog<NotAllowed>(NotAllowedArgument::REASON(
            fmt::format("Not support in current state. IPv4 Source is dhcp.\n",
                        interfaceName())
                .c_str()));
    }

    normalizeGateway<stdplus::In4Addr>(value);

    if (value == EthernetInterfaceIntf::defaultGateway())
    {
        log<level::ERR>(
            fmt::format("backup gateway provided is same as default gateway.\n",
                        interfaceName())
                .c_str());
        elog<NotAllowed>(NotAllowedArgument::REASON(
            fmt::format("backup gateway provided is same as default gateway.\n",
                        interfaceName())
                .c_str()));
    }

    EthernetInterfaceIntf::backupGateway(value);
    writeConfigurationFile();
    writeIfaceStateFile(interfaceName());
    manager.get().reloadConfigs();

    return value;
}

/** Get value of BackupGatewayMACAddress */
std::string EthernetInterface::backupGatewayMACAddress() const
{
    if (!EthernetInterfaceIntf::ipv4Enable())
    {
        return {};
    }

    if (EthernetInterfaceIntf::dhcp4())
    {
        return {};
    }

    if (EthernetInterfaceIntf::backupGateway().empty())
    {
        return {};
    }

    std::string command =
        std::string("ip neigh get ") +
        EthernetInterfaceIntf::backupGateway().c_str() + std::string(" dev ") +
        interfaceName().c_str() + std::string(" 2>/dev/null");

    char data[80] = {0};

    FILE* fp = NULL;
    fp = popen(command.c_str(), "r");
    if (fp == NULL)
    {
        return {"00:00:00:00:00:00"};
    }

    if (fgets(data, sizeof(data), fp) == NULL)
    {
        pclose(fp);
        return {"00:00:00:00:00:00"};
    }
    pclose(fp);

    std::stringstream ss(data);

    std::string ip, dev, devname, addrtype, mac, state;

    ss >> ip >> dev >> devname >> addrtype >> mac >> state;

    std::regex mac_regex("^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$");

    if (std::regex_match(mac, mac_regex) == false)
    {
        return {"00:00:00:00:00:00"};
    }

    return mac;
}

void EthernetInterface::migrateIPIndex(std::string dst)
{
    auto it_dst = manager.get().interfaces.find(dst);
    if (it_dst != manager.get().interfaces.end())
    {
        it_dst->second->ipv4IndexUsedList = std::move(this->ipv4IndexUsedList);
        it_dst->second->ipv6IndexUsedList = std::move(this->ipv6IndexUsedList);
    }
}

#if ENABLE_BOND_SUPPORT
void EthernetInterface::updateBondConfBackupForSlaveMAC(std::string newMAC,
                                                        std::string interface)
{
    std::ofstream ofs;
    std::ifstream ifs;

    ifs.open(config::pathForIntfConf(manager.get().getBondingConfBakDir(),
                                     interface));
    if (!ifs.is_open())
    {
        log<level::INFO>(
            "updateBondConfBackupForSlaveMAC slave configuration file not opened.\n");
    }

    std::stringstream buffer;
    buffer << ifs.rdbuf();
    std::string fileContent = buffer.str();
    ifs.close();

    // Variables to help with parsing the sections
    bool inLinkSection = false;
    std::string searchString = "MACAddress=";
    size_t pos = 0;

    // Iterate through the content to modify only the MACAddress in the [Link]
    // section
    while ((pos = fileContent.find("[", pos)) != std::string::npos)
    {
        // Check if we are entering the [Link] section
        size_t sectionEnd = fileContent.find("]", pos);
        if (sectionEnd != std::string::npos)
        {
            std::string sectionName =
                fileContent.substr(pos + 1, sectionEnd - pos - 1);

            // Check if it's the [Link] section
            if (sectionName == "Link")
            {
                inLinkSection = true;
            }
            else
            {
                inLinkSection = false;
            }
        }

        // If we are in the [Link] section, find and replace the MAC address
        if (inLinkSection)
        {
            size_t macPos = fileContent.find(searchString, pos);
            if (macPos != std::string::npos)
            {
                size_t macEnd = fileContent.find("\n", macPos);
                fileContent.replace(macPos + searchString.length(),
                                    macEnd - macPos - searchString.length(),
                                    newMAC);
                break; // After replacing, exit as we only need to update the
                       // first MAC address in [Link]
            }
        }
        pos++; // Move to the next section
    }

    ofs.open(config::pathForIntfConf(manager.get().getBondingConfBakDir(),
                                     interface));
    if (!ofs.is_open())
    {
        log<level::INFO>(
            "updateBondConfBackupForSlaveMAC slave configuration file not opened.\n");
    }

    ofs << fileContent;
    ofs.close();
}
#endif

} // namespace network
} // namespace phosphor
