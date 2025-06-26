#include "network_manager.hpp"

#include "config_parser.hpp"
#include "garp_control.hpp"
#include "ipaddress.hpp"
#include "system_queries.hpp"
#include "types.hpp"
#include "util.hpp"

#include <linux/if_addr.h>
#include <linux/neighbour.h>
#include <net/if.h>
#include <net/if_arp.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/message.hpp>
#include <stdplus/numeric/str.hpp>
#include <stdplus/pinned.hpp>
#include <stdplus/print.hpp>
#include <stdplus/str/cat.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/State/BMC/server.hpp>

#include <filesystem>
#include <format>

constexpr char ARPCONTROL_CONF_DIR[] = "/etc/arpcontrol";
constexpr char INTERFACE_CONF_DIR[] = "/etc/interface";
#if ENABLE_BOND_SUPPORT
constexpr char BONDING_CONF_BAK_DIR[] = "/etc/interface/bonding";
#endif
constexpr auto BMC_STATE_PROP_INTERFACE = "xyz.openbmc_project.State.BMC";
constexpr auto BMC_STATE_SERVICE_PATH = "/xyz/openbmc_project/state/bmc0";
constexpr char DNS_CONF_DIR[] = "/etc/dns.d";

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using Argument = xyz::openbmc_project::Common::InvalidArgument;
using std::literals::string_view_literals::operator""sv;

static constexpr const char* userMgrObjBasePath = "/xyz/openbmc_project/user";
static constexpr const char* userMgrInterface =
    "xyz.openbmc_project.User.Manager";
static constexpr const char* propNameAllPrivileges = "AllPrivileges";

std::unique_ptr<sdbusplus::bus::match_t> usrMgmtSignal(nullptr);

static constexpr const char enabledMatch[] =
    "type='signal',sender='org.freedesktop.network1',path_namespace='/org/"
    "freedesktop/network1/"
    "link',interface='org.freedesktop.DBus.Properties',member='"
    "PropertiesChanged',arg0='org.freedesktop.network1.Link',";

Manager::Manager(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                 stdplus::PinnedRef<DelayedExecutor> reload,
                 stdplus::zstring_view objPath,
                 const std::filesystem::path& confDir) :
    ManagerIface(bus, objPath.c_str(), ManagerIface::action::defer_emit),
    reload(reload), bus(bus), objPath(std::string(objPath)), confDir(confDir),
    systemdNetworkdEnabledMatch(
        bus, enabledMatch,
        [man = stdplus::PinnedRef(*this)](sdbusplus::message_t& m) {
    std::string intf;
    std::unordered_map<std::string, std::variant<std::string>> values;
    try
    {
        m.read(intf, values);
        auto it = values.find("AdministrativeState");
        if (it == values.end())
        {
            return;
        }
        const std::string_view obj = m.get_path();
        auto sep = obj.rfind('/');
        if (sep == obj.npos || sep + 3 > obj.size())
        {
            throw std::invalid_argument("Invalid obj path");
        }
        auto ifidx = stdplus::StrToInt<10, uint16_t>{}(obj.substr(sep + 3));
        const auto& state = std::get<std::string>(it->second);
        man.get().handleAdminState(state, ifidx);
    }
    catch (const std::exception& e)
    {
        lg2::error("AdministrativeState match parsing failed: {ERROR}", "ERROR",
                   e);
    }
})
{
    reload.get().setCallback([self = stdplus::PinnedRef(*this)]() {
        for (auto& hook : self.get().reloadPreHooks)
        {
            try
            {
                hook();
            }
            catch (const std::exception& ex)
            {
                lg2::error("Failed executing reload hook, ignoring: {ERROR}",
                           "ERROR", ex);
            }
        }
        self.get().reloadPreHooks.clear();
        try
        {
            self.get()
                .bus.get()
                .new_method_call("org.freedesktop.network1",
                                 "/org/freedesktop/network1",
                                 "org.freedesktop.network1.Manager", "Reload")
                .call();
            lg2::info("Reloaded systemd-networkd");
        }
        catch (const sdbusplus::exception_t& ex)
        {
            lg2::error("Failed to reload configuration: {ERROR}", "ERROR", ex);
            self.get().reloadPostHooks.clear();
        }
        for (auto& hook : self.get().reloadPostHooks)
        {
            try
            {
                hook();
            }
            catch (const std::exception& ex)
            {
                lg2::error("Failed executing reload hook, ignoring: {ERROR}",
                           "ERROR", ex);
            }
        }

#ifdef AMI_IP_ADVANCED_ROUTING_SUPPORT
        self.get().advanced_route_cond_var.notify_one();
#endif
        self.get().reloadPostHooks.clear();
    });
    std::vector<
        std::tuple<int32_t, std::string, sdbusplus::message::object_path>>
        links;
    try
    {
        auto rsp = bus.get()
                       .new_method_call("org.freedesktop.network1",
                                        "/org/freedesktop/network1",
                                        "org.freedesktop.network1.Manager",
                                        "ListLinks")
                       .call();
        rsp.read(links);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        // Any failures are systemd-network not being ready
    }
    for (const auto& link : links)
    {
        unsigned ifidx = std::get<0>(link);
        stdplus::ToStrHandle<stdplus::IntToStr<10, unsigned>> tsh;
        auto obj = stdplus::strCat("/org/freedesktop/network1/link/_3"sv,
                                   tsh(ifidx));
        auto req =
            bus.get().new_method_call("org.freedesktop.network1", obj.c_str(),
                                      "org.freedesktop.DBus.Properties", "Get");
        req.append("org.freedesktop.network1.Link", "AdministrativeState");
        auto rsp = req.call();
        std::variant<std::string> val;
        rsp.read(val);
        handleAdminState(std::get<std::string>(val), ifidx);
    }

    std::filesystem::create_directories(confDir);
    systemConf = std::make_unique<phosphor::network::SystemConfiguration>(
        bus, (this->objPath / "config").str, *this);
    firewallConf = std::make_unique<phosphor::network::firewall::Configuration>(
        bus, (this->objPath / "firewall").str, *this);
#if NSUPDATE_SUPPORT
    ddnsConf = std::make_unique<phosphor::network::dns::Configuration>(
        bus, (this->objPath / "dns").str, *this);
#endif
    setConfDir(confDir);

    initCompleted = false;
    signals = initSignals();
    registerSignal(bus);

#ifdef AMI_IP_ADVANCED_ROUTING_SUPPORT
    advanced_route_lock = std::unique_lock(advanced_route_mutex);
    advanced_route_worker = std::thread(&Manager::AdvancedRoute, this);
#endif

    initSupportedPrivilges();
}

std::string getUserService(sdbusplus::bus::bus& bus, const std::string& intf,
                           const std::string& path)
{
    auto mapperCall = bus.new_method_call("xyz.openbmc_project.ObjectMapper",
                                          "/xyz/openbmc_project/object_mapper",
                                          "xyz.openbmc_project.ObjectMapper",
                                          "GetObject");

    mapperCall.append(path);
    mapperCall.append(std::vector<std::string>({intf}));

    auto mapperResponseMsg = bus.call(mapperCall);

    std::map<std::string, std::vector<std::string>> mapperResponse;
    mapperResponseMsg.read(mapperResponse);

    if (mapperResponse.begin() == mapperResponse.end())
    {
        throw std::runtime_error("ERROR in reading the mapper response");
    }

    return mapperResponse.begin()->first;
}

std::string Manager::getUserServiceName()
{
    static std::string userMgmtService;
    if (userMgmtService.empty())
    {
        try
        {
            userMgmtService = getUserService(bus, userMgrInterface,
                                             userMgrObjBasePath);
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("Exception caught in getUserServiceName.");
            userMgmtService.clear();
        }
    }
    return userMgmtService;
}

void Manager::initSupportedPrivilges()
{
    std::string userServiceName = getUserServiceName();
    if (!userServiceName.empty())
    {
        auto method = bus.get().new_method_call(
            getUserServiceName().c_str(), userMgrObjBasePath,
            "org.freedesktop.DBus.Properties", "Get");
        method.append(userMgrInterface, propNameAllPrivileges);

        auto reply = bus.get().call(method);
        if (reply.is_method_error())
        {
            log<level::DEBUG>("get-property AllPrivileges failed",
                              entry("OBJPATH:%s", userMgrObjBasePath),
                              entry("INTERFACE:%s", userMgrInterface));
            return;
        }

        std::variant<std::vector<std::string>> result;
        reply.read(result);

        supportedPrivList = std::get<std::vector<std::string>>(result);
    }

    // Resgister the signal
    if (usrMgmtSignal == nullptr)
    {
        log<level::DEBUG>("Registering User.Manager propertychange signal.");
        usrMgmtSignal = std::make_unique<sdbusplus::bus::match_t>(
            bus,
            sdbusplus::bus::match::rules::propertiesChanged(userMgrObjBasePath,
                                                            userMgrInterface),
            [&](sdbusplus::message::message& msg) {
                log<level::DEBUG>("UserMgr properties changed signal");
                std::map<std::string, DbusVariant> props;
                std::string iface;
                msg.read(iface, props);
                for (const auto& t : props)
                {
                    if (t.first == propNameAllPrivileges)
                    {
                        supportedPrivList =
                            std::get<std::vector<std::string>>(t.second);
                    }
                }
            });
    }
    return;
}

void Manager::createInterface(const AllIntfInfo& info, bool enabled)
{
    if (ignoredIntf.find(info.intf.idx) != ignoredIntf.end())
    {
        return;
    }
    if (auto it = interfacesByIdx.find(info.intf.idx);
        it != interfacesByIdx.end())
    {
        if (info.intf.name && *info.intf.name != it->second->interfaceName())
        {
            interfaces.erase(it->second->interfaceName());
            interfacesByIdx.erase(it);
        }
        else
        {
            it->second->updateInfo(info.intf);
            return;
        }
    }
    else if (info.intf.name)
    {
        auto it = interfaces.find(*info.intf.name);
        if (it != interfaces.end())
        {
            if(info.intf.vlan_id)
            {
                interfacesByIdx.insert_or_assign(info.intf.idx, it->second.get());
            }
            it->second->updateInfo(info.intf);
            return;
        }
    }
    if (!info.intf.name)
    {
        lg2::error("Can't create interface without name: {NET_IDX}", "NET_IDX",
                   info.intf.idx);
        return;
    }
    config::Parser config(config::pathForIntfConf(confDir, *info.intf.name));
#if ENABLE_BOND_SUPPORT
    if (fs::exists("/sys/class/net/bond0/bonding/active_slave") &&
        info.intf.name.value() != "bond0")
    {
        config = config::pathForIntfConf(bondingConfBakDir, *info.intf.name);
    }
#endif
    auto intf = std::make_unique<EthernetInterface>(
        bus, *this, info, objPath.str, config, enabled);
    intf->loadNameServers(config);
    intf->loadNTPServers(config);
    intf->loadDomainNames();
    auto ptr = intf.get();
    interfaces.insert_or_assign(*info.intf.name, std::move(intf));
    interfacesByIdx.insert_or_assign(info.intf.idx, ptr);
}

void Manager::addInterface(const InterfaceInfo& info)
{
    if (info.type != ARPHRD_ETHER)
    {
        ignoredIntf.emplace(info.idx);
        return;
    }
    if (info.name)
    {
        const auto& ignored = internal::getIgnoredInterfaces();
        if (ignored.find(*info.name) != ignored.end())
        {
            static std::unordered_set<std::string> ignored;
            if (!ignored.contains(*info.name))
            {
                ignored.emplace(*info.name);
                lg2::info("Ignoring interface {NET_INTF}", "NET_INTF",
                          *info.name);
            }
            ignoredIntf.emplace(info.idx);
            return;
        }
    }

    auto infoIt = intfInfo.find(info.idx);
    if (infoIt != intfInfo.end())
    {
        infoIt->second.intf = info;
    }
    else
    {
        infoIt = std::get<0>(intfInfo.emplace(info.idx, AllIntfInfo{info}));
    }

    if (auto it = systemdNetworkdEnabled.find(info.idx);
        it != systemdNetworkdEnabled.end())
    {
        createInterface(infoIt->second, it->second);
    }
}

void Manager::removeInterface(const InterfaceInfo& info)
{
    auto iit = interfacesByIdx.find(info.idx);
    auto nit = interfaces.end();
    if (info.name)
    {
        nit = interfaces.find(*info.name);
        if (nit != interfaces.end() && iit != interfacesByIdx.end() &&
            nit->second.get() != iit->second)
        {
            stdplus::print(stderr, "Removed interface desync detected\n");
            fflush(stderr);
            std::abort();
        }
    }
    else if (iit != interfacesByIdx.end())
    {
        for (nit = interfaces.begin(); nit != interfaces.end(); ++nit)
        {
            if (nit->second.get() == iit->second)
            {
                break;
            }
        }
    }

    if (iit != interfacesByIdx.end())
    {
        interfacesByIdx.erase(iit);
    }
    else
    {
        ignoredIntf.erase(info.idx);
    }
    if (nit != interfaces.end())
    {
        interfaces.erase(nit);
    }
    intfInfo.erase(info.idx);
}

void Manager::addAddress(const AddressInfo& info)
{
    if (info.flags & IFA_F_DEPRECATED)
    {
        return;
    }
    if (auto it = intfInfo.find(info.ifidx); it != intfInfo.end())
    {
        it->second.addrs.insert_or_assign(info.ifaddr, info);
        auto name = it->second.intf.name;
        if (auto it = interfaces.find(name.value()); it != interfaces.end())
        {
            it->second->addAddr(info);
        }
    }
    else if (!ignoredIntf.contains(info.ifidx))
    {
        throw std::runtime_error(
            std::format("Interface `{}` not found for addr", info.ifidx));
    }
}

void Manager::removeAddress(const AddressInfo& info)
{
    if (auto it = interfacesByIdx.find(info.ifidx); it != interfacesByIdx.end())
    {
        it->second->addrs.erase(info.ifaddr);
        auto name = it->second->interfaceName();
        if (auto it = interfaces.find(name); it != interfaces.end())
        {
            it->second->addrs.erase(info.ifaddr);
        }
    }
}

void Manager::addNeighbor(const NeighborInfo& info)
{
    if (!(info.state & NUD_PERMANENT) || !info.addr)
    {
        return;
    }
    if (auto it = intfInfo.find(info.ifidx); it != intfInfo.end())
    {
        it->second.staticNeighs.insert_or_assign(*info.addr, info);
        if (auto it = interfacesByIdx.find(info.ifidx);
            it != interfacesByIdx.end())
        {
            it->second->addStaticNeigh(info);
        }
    }
    else if (!ignoredIntf.contains(info.ifidx))
    {
        throw std::runtime_error(
            std::format("Interface `{}` not found for neigh", info.ifidx));
    }
}

void Manager::removeNeighbor(const NeighborInfo& info)
{
    if (!info.addr)
    {
        return;
    }
    if (auto it = intfInfo.find(info.ifidx); it != intfInfo.end())
    {
        it->second.staticNeighs.erase(*info.addr);
        if (auto it = interfacesByIdx.find(info.ifidx);
            it != interfacesByIdx.end())
        {
            it->second->staticNeighbors.erase(*info.addr);
        }
    }
}

void Manager::addDefGw(unsigned ifidx, stdplus::InAnyAddr addr)
{
    if (auto it = intfInfo.find(ifidx); it != intfInfo.end())
    {
        std::visit(
            [&](auto addr) {
            if constexpr (std::is_same_v<stdplus::In4Addr, decltype(addr)>)
            {

                if (auto it1 = interfacesByIdx.find(ifidx);
                    it1 != interfacesByIdx.end())
                {
                    if (!it1->second->EthernetInterfaceIntf::dhcp4())
                    {
                        const config::Parser& ifaceConfig(
                            config::pathForIntfConf(getConfDir(),
                                        it1->second->interfaceName()));
                        auto gw4 = stdplus::fromStr<stdplus::In4Addr>(
                            getIPv4DefaultGateway(ifaceConfig));
                        it->second.defgw4.emplace(gw4);
                    }
                    else
                    {
                        it->second.defgw4.emplace(addr);
                    }
                }
            }
            else
            {
                static_assert(std::is_same_v<stdplus::In6Addr, decltype(addr)>);
                it->second.defgw6.emplace(addr);
            }
        },
            addr);
        if (auto it = interfacesByIdx.find(ifidx); it != interfacesByIdx.end())
        {
            std::visit(
                [&](auto addr) {
                if constexpr (std::is_same_v<stdplus::In4Addr, decltype(addr)>)
                {
                    if (!it->second->EthernetInterfaceIntf::dhcp4())
                    {
                        const config::Parser& ifaceConfig(
                            config::pathForIntfConf(getConfDir(),
                                        it->second->interfaceName()));
                        it->second->EthernetInterfaceIntf::defaultGateway(
                            getIPv4DefaultGateway(ifaceConfig));
                    }
                    else
                    {
                        it->second->EthernetInterfaceIntf::defaultGateway(
                            stdplus::toStr(addr));
                    }
                    auto [mac, prefixLength] =
                        it->second->getDwMacAddrByIP(stdplus::toStr(addr));
                    addNeighbor(NeighborInfo{
                        .ifidx = ifidx,
                        .state = NUD_PERMANENT,
                        .addr = stdplus::fromStr<stdplus::In4Addr>(
                            it->second
                                ->EthernetInterfaceIntf::defaultGateway()),
                        .mac = stdplus::fromStr<stdplus::EtherAddr>(
                            mac.value_or("00:00:00:00:00:00")),
                        .prefixLength = prefixLength

                    });
                }
                else
                {
                    static_assert(
                        std::is_same_v<stdplus::In6Addr, decltype(addr)>);
                    it->second->EthernetInterfaceIntf::defaultGateway6(
                        stdplus::toStr(addr));
                }
            },
                addr);
        }
    }
    else if (!ignoredIntf.contains(ifidx))
    {
        lg2::error("Interface {NET_IDX} not found for gw", "NET_IDX", ifidx);
    }
}

void Manager::removeDefGw(unsigned ifidx, stdplus::InAnyAddr addr)
{
    if (auto it = intfInfo.find(ifidx); it != intfInfo.end())
    {
        std::visit(
            [&](auto addr) {
            if constexpr (std::is_same_v<stdplus::In4Addr, decltype(addr)>)
            {
                if (it->second.defgw4 == addr)
                {
                    it->second.defgw4.reset();
                }
            }
            else
            {
                static_assert(std::is_same_v<stdplus::In6Addr, decltype(addr)>);
                if (it->second.defgw6 == addr)
                {
                    it->second.defgw6.reset();
                }
            }
        },
            addr);
        if (auto it = interfacesByIdx.find(ifidx); it != interfacesByIdx.end())
        {
            std::visit(
                [&](auto addr) {
                if constexpr (std::is_same_v<stdplus::In4Addr, decltype(addr)>)
                {
                    stdplus::ToStrHandle<stdplus::ToStr<stdplus::In4Addr>> tsh;
                    if (it->second->defaultGateway() == tsh(addr))
                    {
                        if (!it->second->EthernetInterfaceIntf::defaultGateway()
                                 .empty())
                        {
                            removeNeighbor(NeighborInfo{
                                .ifidx = if_nametoindex(
                                    it->second->interfaceName().c_str()),
                                .addr = stdplus::fromStr<stdplus::In4Addr>(
                                    it->second->EthernetInterfaceIntf::
                                        defaultGateway())});
                        }
                        it->second->EthernetInterfaceIntf::defaultGateway("");
                    }
                }
                else
                {
                    static_assert(
                        std::is_same_v<stdplus::In6Addr, decltype(addr)>);
                    stdplus::ToStrHandle<stdplus::ToStr<stdplus::In6Addr>> tsh;
                    if (it->second->defaultGateway6() == tsh(addr))
                    {
                        it->second->EthernetInterfaceIntf::defaultGateway6("");
                    }
                }
            },
                addr);
        }
    }
}

ObjectPath Manager::vlan(std::string interfaceName, uint32_t id)
{
    if (id <= 1 || id >= 4095)
    {
        lg2::error("VLAN ID {NET_VLAN} is not valid", "NET_VLAN", id);
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("VLANId"),
            Argument::ARGUMENT_VALUE(std::to_string(id).c_str()));
    }

    auto it = interfaces.find(interfaceName);
    if (it == interfaces.end())
    {
        using ResourceErr =
            phosphor::logging::xyz::openbmc_project::Common::ResourceNotFound;
        elog<ResourceNotFound>(ResourceErr::RESOURCE(interfaceName.c_str()));
    }
    return it->second->createVLAN(id);
}

bool Manager::createDefaultARPControlFiles(bool force)
{
    auto isCreated = false;
    try
    {
        // Directory would have created before with
        // setConfDir function.
        if (force)
        {
            // Factory Reset case
            // we need to forcefully write the files
            // so delete the existing ones.
            if (fs::is_directory(arpConfDir))
            {
                for (const auto& file : fs::directory_iterator(arpConfDir))
                {
                    fs::remove(file.path());
                }
            }
        }

        auto interfaceStrList = phosphor::network::getInterfaces();
        for (const auto& interface : interfaceStrList)
        {
            // if the interface has '.' in the name, it means that this is a
            // VLAN - don't create the network file.
            if (interface.find(".") != std::string::npos)
            {
                continue;
            }

            auto fileName = phosphor::network::arpPrefix + interface +
                            phosphor::network::arpSurffix;

            fs::path filePath = arpConfDir;
            filePath /= fileName;

            // create the interface specific network file
            // if not exist or we forcefully wants to write
            // the network file.

            if (force || !fs::is_regular_file(filePath.string()))
            {
                writeARPControlDefault(filePath.string());
                log<level::INFO>("Created the default ARP Control file.",
                                 entry("INTERFACE=%s", interface.c_str()));
                isCreated = true;
            }
        }
    }
    catch (std::exception& e)
    {
        log<level::ERR>("Unable to create the default ARP Control file");
    }
    return isCreated;
}

void Manager::reset()
{
    for (const auto& dirent : std::filesystem::directory_iterator(confDir))
    {
        std::error_code ec;
        std::filesystem::remove(dirent.path(), ec);
    }

    for (const auto& dirent : std::filesystem::directory_iterator(ifaceConfDir))
    {
        std::error_code ec;
        std::filesystem::remove(dirent.path(), ec);
    }

    lg2::info("Network data purged.");

    if (!createDefaultARPControlFiles(true))
    {
        log<level::ERR>("Network ARP Control Factory Reset failed.");
        return;
    }
    for (const auto& intf : interfaces)
    {
        intf.second->loadARPControl();
    }
}

void Manager::writeToConfigurationFile()
{
    // write all the static ip address in the systemd-network conf file
    for (const auto& intf : interfaces)
    {
        intf.second->writeConfigurationFile();
    }
}

void Manager::handleAdminState(std::string_view state, unsigned ifidx)
{
    if (state == "initialized" || state == "linger")
    {
        systemdNetworkdEnabled.erase(ifidx);
    }
    else
    {
        bool managed = state != "unmanaged";
        systemdNetworkdEnabled.insert_or_assign(ifidx, managed);
        if (auto it = interfacesByIdx.find(ifidx); it != interfacesByIdx.end())
        {
            it->second->EthernetInterfaceIntf::nicEnabled(managed);
        }
        else if (auto it = intfInfo.find(ifidx); it != intfInfo.end())
        {
            createInterface(it->second, managed);
        }
    }
}

std::map<std::string, std::unique_ptr<sdbusplus::bus::match_t>>
    Manager::initSignals()
{
    std::map<std::string, std::unique_ptr<sdbusplus::bus::match_t>> mp;
    mp["BMCStateSignal"] = nullptr;
    return mp;
}

void Manager::registerSignal(sdbusplus::bus::bus& bus)
{
    for (auto& signal : signals)
    {
        if (signal.second == nullptr && signal.first == "BMCStateSignal")
        {
            signal.second = std::make_unique<sdbusplus::bus::match_t>(
                bus,
                sdbusplus::bus::match::rules::propertiesChanged(
                    BMC_STATE_SERVICE_PATH, BMC_STATE_PROP_INTERFACE),
                [&](sdbusplus::message::message& msg) {
                std::map<
                    std::string,
                    std::variant<std::string, std::vector<std::string>, bool>>
                    props;
                std::string iface;
                msg.read(iface, props);
                for (const auto& t : props)
                {
                    if (t.first == "CurrentBMCState" && !initCompleted)
                    {
                        sdbusplus::common::xyz::openbmc_project::state::BMC::
                            BMCState state =
                                sdbusplus::common::xyz::openbmc_project::state::
                                    BMC::convertBMCStateFromString(
                                        std::get<std::string>(t.second));
                        if (state == sdbusplus::common::xyz::openbmc_project::
                                         state::BMC::BMCState::Ready)
                        {
                            auto lists = getGateway6FromFile();
                            for (auto line : lists)
                            {
                                std::stringstream ss(line);
                                std::string dstIP, dstPrefix, srcIP, srcPrefix,
                                    nextHop, metric, count, useCount, devName,
                                    flags;
                                ss >> dstIP >> dstPrefix >> srcIP >>
                                    srcPrefix >> nextHop >> flags >> metric >>
                                    count >> useCount >> devName;
                                if (devName.find("usb") != std::string::npos)
                                    continue;
                                int flagInt = std::stoul(flags, 0, 16);
                                if (((flagInt & 0x400) == 0x400) &&
                                    nextHop.compare(
                                        "00000000000000000000000000000000") !=
                                        0)
                                {
                                    if (auto it = interfaces.find(devName);
                                        it != interfaces.end())
                                    {
                                        if (it->second
                                                ->EthernetInterfaceIntf::
                                                    defaultGateway6()
                                                .empty())
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
                                            it->second->EthernetInterfaceIntf::
                                                defaultGateway6(
                                                    std::string{buf}, true);
                                        }
                                    }
                                }
                            }
                            {
                                for (auto it = interfaces.begin(); it != interfaces.end(); it++)
                                {
                                    if (!it->second->EthernetInterfaceIntf::ipv6Enable())
                                    {
                                        lg2::info("Flush Ipv6 address on dev {NAME}\n", "NAME", it->first);
                                        std::system(fmt::format("ip -6 addr flush dev {}", it->first).c_str());
                                    }
                                }
                            }
                            initCompleted = true;
                        }
                    }
                }
            });
        }
    }
}

std::vector<std::string> Manager::getGateway6FromFile()
{
    std::ifstream ifs("/proc/net/ipv6_route");
    std::string line;
    std::vector<std::string> vec;
    if (!ifs)
    {
        log<level::INFO>("/proc/net/ipv6_route not opened\n");
        return vec;
    }
    while (std::getline(ifs, line))
    {
        vec.push_back(line);
    }

    ifs.close();
    return vec;
}

std::vector<std::string> Manager::getGatewayFromFile()
{
    std::ifstream ifs("/proc/net/route");
    std::string line;
    std::vector<std::string> vec;
    if (!ifs)
    {
        log<level::INFO>("/proc/net/route not opened\n");
        return vec;
    }
    while (std::getline(ifs, line))
    {
        vec.push_back(line);
    }

    ifs.close();
    return vec;
}

void Manager::reconfigLink(int ifidx)
{
    try
    {
        auto method = bus.get()
            .new_method_call("org.freedesktop.network1",
                                "/org/freedesktop/network1",
                                "org.freedesktop.network1.Manager", "ReconfigureLink");
        method.append(ifidx);
        bus.get().call(method);
        lg2::info("Re configured Link #{LINK}", "LINK", ifidx);
    }
    catch (const sdbusplus::exception_t& ex)
    {
        lg2::error("Failed to reconfigure: {ERROR}", "ERROR", ex);
    }
}

void Manager::setConfDir(const fs::path& dir)
{
    confDir = dir;

    if (!fs::exists(confDir))
    {
        if (!fs::create_directories(confDir))
        {
            log<level::ERR>("Unable to create the network conf dir",
                            entry("DIR=%s", confDir.c_str()));
            elog<InternalFailure>();
        }
    }
    fs::path arpDir(ARPCONTROL_CONF_DIR);
    arpConfDir = arpDir;

    if (!fs::exists(arpConfDir))
    {
        if (!fs::create_directories(arpConfDir))
        {
            log<level::ERR>("Unable to create the arpcontrol conf dir",
                            entry("DIR=%s", arpConfDir.c_str()));
            elog<InternalFailure>();
        }
    }

    fs::path ifaceDir(INTERFACE_CONF_DIR);
    ifaceConfDir = ifaceDir;
    if (!fs::exists(ifaceConfDir))
    {
        if (!fs::create_directories(ifaceConfDir))
        {
            log<level::ERR>("Unable to create the Interface conf dir",
                            entry("DIR=%s", ifaceConfDir.c_str()));
            elog<InternalFailure>();
        }
    }

    fs::path ipTablesDir(firewall::CUSTOM_IPTABLES_DIR);
    customIPTablesDir = ipTablesDir;
    if (!fs::exists(customIPTablesDir))
    {
        if (!fs::create_directories(customIPTablesDir))
        {
            log<level::ERR>("Unable to create the Custom IPTables Rule dir",
                            entry("DIR=%s", customIPTablesDir.c_str()));
            elog<InternalFailure>();
        }
    }

#if ENABLE_BOND_SUPPORT
    fs::path bondingDir(BONDING_CONF_BAK_DIR);
    bondingConfBakDir = bondingDir;
    if (!fs::exists(bondingConfBakDir))
    {
        if (!fs::create_directories(bondingConfBakDir))
        {
            log<level::ERR>("Unable to create the bonding conf bak dir",
                            entry("DIR=%s", bondingConfBakDir.c_str()));
            elog<InternalFailure>();
        }
    }
#endif
}

Manager::~Manager()
{
#ifdef AMI_IP_ADVANCED_ROUTING_SUPPORT
    advanced_route_worker.std::thread::~thread();
#endif
}

#ifdef AMI_IP_ADVANCED_ROUTING_SUPPORT
void Manager::AdvancedRoute()
{
    while (true)
    {
        advanced_route_cond_var.wait(advanced_route_lock);
        std::this_thread::sleep_for(std::chrono::seconds(5));

        for (auto it = interfaces.begin(); it != interfaces.end(); it++)
        {
            auto ifname = it->first;
            execute("/usr/bin/ipv4-advanced-route.sh", "ipv4-advanced-route.sh",
                    ifname.c_str(), it->second->linkUp() ? "UP" : "DOWN");

            execute("/usr/bin/ipv6-advanced-route.sh", "ipv6-advanced-route.sh",
                    ifname.c_str(), it->second->linkUp() ? "UP" : "DOWN");
        }
    }
}
#endif

#if ENABLE_BOND_SUPPORT
ObjectPath Manager::bond(std::string activeSlave, uint8_t miiMonitor)
{
    if (miiMonitor == 0 || miiMonitor > 100)
    {
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("MIIMonitor"),
            Argument::ARGUMENT_VALUE(stdplus::toStr(miiMonitor).c_str()));
    }

    auto it = interfaces.find(activeSlave);
    if (it == interfaces.end())
    {
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("ActiveSlave"),
                              Argument::ARGUMENT_VALUE(activeSlave.c_str()));
    }
    else if ((activeSlave.compare("bond0") == 0) ||
             (activeSlave.compare("hostusb0") == 0))
    {
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("ActiveSlave"),
                              Argument::ARGUMENT_VALUE(activeSlave.c_str()));
    }
    return it->second->createBond(activeSlave, miiMonitor);
}
#endif
} // namespace network
} // namespace phosphor
