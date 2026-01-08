#include "host_interface.hpp"

#include "config_parser.hpp"
#include "util.hpp"

#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <sdbusplus/bus.hpp>
#include <sdbusplus/message.hpp>
#include <stdplus/str/conv.hpp>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <format>
#include <iostream>
#include <memory>
#include <string_view>

namespace phosphor
{
namespace network
{
namespace hostintf
{

namespace fs = std::filesystem;
using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using NotAllowed = sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;
using Reason = xyz::openbmc_project::Common::NotAllowed::REASON;

static auto makeObjPath(std::string_view root, stdplus::SubnetAny addr)
{
    auto ret = sdbusplus::message::object_path(std::string(root));
    stdplus::ToStrHandle<stdplus::ToStr<stdplus::SubnetAny>> tsh;
    ret /= tsh(addr);
    return ret;
}

template <typename T>
struct Proto
{};

template <>
struct Proto<stdplus::In4Addr>
{
    static inline constexpr auto value = IP::Protocol::IPv4;
};

template <>
struct Proto<stdplus::In6Addr>
{
    static inline constexpr auto value = IP::Protocol::IPv6;
};

HostIPAddress::HostIPAddress(sdbusplus::bus_t& bus, std::string_view objRoot,
                             stdplus::PinnedRef<HostInterface> parent,
                             stdplus::SubnetAny addr, AddressOrigin origin,
                             uint8_t idx) :
    HostIPAddress(bus, makeObjPath(objRoot, addr), parent, addr, origin, idx)
{}

HostIPAddress::HostIPAddress(
    sdbusplus::bus_t& bus, sdbusplus::message::object_path objPath,
    stdplus::PinnedRef<HostInterface> parent, stdplus::SubnetAny addr,
    IP::AddressOrigin origin, uint8_t idx) :
    hostIPIfaces(bus, objPath.str.c_str(), hostIPIfaces::action::defer_emit),
    parent(parent), objPath(std::move(objPath))
{
    IP::address(stdplus::toStr(addr.getAddr()), true);
    IP::prefixLength(addr.getPfx(), true);
    IP::type(std::visit([](auto v) { return Proto<decltype(v)>::value; },
                        addr.getAddr()),
             true);
    IP::origin(origin, true);
    IP::idx(idx, true);
    emit_object_added();
}

std::string HostIPAddress::address(std::string ipAddress)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

uint8_t HostIPAddress::prefixLength(uint8_t prefix)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

uint8_t HostIPAddress::idx(uint8_t index)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

std::string HostIPAddress::gateway(std::string gateway)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

IP::Protocol HostIPAddress::type(IP::Protocol type)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

IP::AddressOrigin HostIPAddress::origin(IP::AddressOrigin origin)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

void HostIPAddress::delete_()
{
    std::unique_ptr<HostIPAddress> ptr;
    auto& addrs = parent.get().addrs;
    for (auto it = addrs.begin(); it != addrs.end(); ++it)
    {
        if (it->second.get() == this)
        {
            ptr = std::move(it->second);
            addrs.erase(it);
            break;
        }
    }
}

int HostInterface::configureHostInterface(const std::string& ipaddress,
                                          const uint8_t prefixLength,
                                          const uint8_t ifindex)
{
    struct ifreq ifr;

    char if_name[IFNAMSIZ] = {0};

    if (if_indextoname(ifindex, if_name) == NULL)
    {
        log<level::ERR>(
            fmt::format("Failed to get interface name for index : = {}",
                        ifindex)
                .c_str());
        return -1;
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        log<level::ERR>(
            fmt::format("Failed to create socket : = {}", strerror(errno))
                .c_str());
        return -1;
    }

    std::strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;

    if (inet_pton(AF_INET, ipaddress.c_str(), &addr.sin_addr) <= 0)
    {
        log<level::ERR>(
            fmt::format("Invalid IP Address : = {}", ipaddress.c_str())
                .c_str());
        close(sockfd);
        return -1;
    }

    // Copy the entire sockaddr structure, not just the address part
    std::memcpy(&ifr.ifr_addr, &addr, sizeof(struct sockaddr));

    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0)
    {
        log<level::ERR>(
            fmt::format("Failed to set IP Address : = {}", strerror(errno))
                .c_str());
        close(sockfd);
        return -1;
    }

    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    uint32_t mask = (prefixLength == 0) ? 0 : (~0U << (32 - prefixLength));

    struct sockaddr_in netmask_addr;
    netmask_addr.sin_family = AF_INET;
    netmask_addr.sin_addr.s_addr = htonl(mask);
    std::memcpy(&ifr.ifr_netmask, &netmask_addr, sizeof(struct sockaddr));

    if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0)
    {
        log<level::ERR>(
            fmt::format("Failed to set netmask : = {}", strerror(errno))
                .c_str());
        close(sockfd);
        return -1;
    }

    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0)
    {
        log<level::ERR>(
            fmt::format("Failed to get interface flags : = {}", strerror(errno))
                .c_str());
        close(sockfd);
        return -1;
    }

    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0)
    {
        log<level::ERR>(
            fmt::format("Failed to set interface flags : = {}", strerror(errno))
                .c_str());
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return 0;
}

HostInterface::HostInterface(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                             stdplus::zstring_view objPath,
                             const InterfaceInfo& info) :
    hostIfaces(bus, objPath.c_str(), hostIfaces::action::defer_emit), bus(bus),
    objPath(std::string(objPath))
{
    const config::Parser& config(
        config::pathForIntfConf(HOST_INTERFACE_CONF_DIR, intfName));

    std::string ipaddress{};
    auto value = config.map.getLastValueString("Network", "IPAddress");
    if (value == nullptr)
    {
        ipaddress = defaultIpAddress;
    }
    else
    {
        ipaddress = *value;
    }

    uint8_t prefixLength;
    value = config.map.getLastValueString("Network", "PrefixLength");
    if (value == nullptr)
    {
        prefixLength = defaultPrefixLength;
    }
    else
    {
        prefixLength = static_cast<uint8_t>(std::stoul(*value, nullptr, 10));
    }

    try
    {
        configureHostInterface(ipaddress, prefixLength, info.idx);
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(
            fmt::format("Failed to configure host interface : e.what() = {}",
                        e.what())
                .c_str());
        std::runtime_error("Configure hostusb0 failed");
    }

    this->ifindex = info.idx;

    createEthernetInterface();

    if (info.mac)
    {
        MacAddressIntf::macAddress(stdplus::toStr(*info.mac), true);
    }

    emit_object_added();
}

void HostInterface::delete_()
{
    // Clean up all IP addresses first
    if (!addrs.empty())
    {
        addrs.clear();
    }

    // Clean up ethernet interface
    if (ethernetInterface)
    {
        ethernetInterface.reset();
    }
}

std::string HostInterface::macAddress(std::string value)
{
    log<level::ERR>("Property update is not allowed\n");
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

void HostInterface::addAddr(const AddressInfo& info)
{
    IP::AddressOrigin origin = IP::AddressOrigin::Static;

    if (info.scope == RT_SCOPE_LINK)
    {
        origin = IP::AddressOrigin::LinkLocal;
    }

    int idx = 0;
    auto it = addrs.find(info.ifaddr);
    if (it != addrs.end())
    {
        return;
    }
    else
    {
        if (origin == IP::AddressOrigin::Static)
        {
            auto tmpAddr = stdplus::toStr(info.ifaddr.getAddr());
            if (tmpAddr.find(".") != std::string::npos)
            {
                for (const auto& [_, addr] : addrs)
                {
                    if (addr->type() == IP::Protocol::IPv4)
                    {
                        runSystemCommand(
                            "/usr/sbin/ip",
                            fmt::format(" addr del {}/{} dev {}",
                                        addr->address(), addr->prefixLength(),
                                        intfName)
                                .c_str());
                    }
                }
            }
        }
    }

    auto addr = addrs.emplace(
        info.ifaddr,
        std::make_unique<HostIPAddress>(bus, std::string_view(objPath), *this,
                                        info.ifaddr, origin, idx));
    writeConfigurationFile(*addr.first->second);
}

void HostInterface::removeAddr(const AddressInfo& info)
{
    auto it = addrs.find(info.ifaddr);
    if (it != addrs.end())
    {
        addrs.erase(it);
    }

    for (const auto& [_, addr] : addrs)
    {
        if (addr->type() == IP::Protocol::IPv4)
        {
            writeConfigurationFile(*addr);
            return;
        }
    }

    fs::remove(config::pathForIntfConf(HOST_INTERFACE_CONF_DIR, intfName));
}

void HostInterface::createEthernetInterface()
{
    try
    {
        // Create an interface using sdbusplus and unique_ptr
        ethernetInterface = std::make_unique<sdbusplus::server::interface_t>(
            bus.get(), objPath.c_str(), ethIntf, vtable, this);
    }
    catch (const std::exception& e)
    {
        // Log error - interface remains nullptr after reset()
        log<level::ERR>(
            fmt::format("Failed to create ethernet interface : {}", e.what())
                .c_str());
        ethernetInterface = nullptr; // Explicit but not necessary after reset()
    }
}

bool HostInterface::arpResponse(bool value)
{
    log<level::ERR>("Property update is not allowed\n");
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

bool HostInterface::gratuitousARP(bool value)
{
    log<level::ERR>("Property update is not allowed\n");
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

uint64_t HostInterface::gratuitousARPInterval(uint64_t interval)
{
    log<level::ERR>("Property update is not allowed\n");
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

void HostInterface::writeConfigurationFile(
    stdplus::PinnedRef<HostIPAddress> addr)
{
    config::Parser config;

    if (addr.get().type() == IP::Protocol::IPv4)
    {
        auto& net = config.map["Network"].emplace_back();
        net["IPAddress"].emplace_back(addr.get().address().c_str());
        net["PrefixLength"].emplace_back(
            fmt::format("{}", addr.get().prefixLength()));
        config.writeFile(
            config::pathForIntfConf(HOST_INTERFACE_CONF_DIR, intfName));
    }
}

int HostInterface::_callback_get_interface_name(
    sd_bus*, const char*, const char*, const char*, sd_bus_message* msg,
    void* context, sd_bus_error* error [[maybe_unused]])
{
    if (msg != nullptr && context != nullptr)
    {
        try
        {
            auto hostObj = static_cast<HostInterface*>(context);
            auto value = hostObj->InterfaceName();
            sdbusplus::message_t(msg).append(value);
        }
        catch (const sdbusplus::exception_t& e)
        {
            return sd_bus_error_set(error, e.name(), e.description());
        }
    }
    else
    {
        // The message or context were null
        log<level::ERR>(
            "Unable to service get interface name property callback");
        return -1;
    }

    return 1;
}

int HostInterface::_callback_get_dhcp4(
    sd_bus*, const char*, const char*, const char*, sd_bus_message* msg,
    void* context, sd_bus_error* error [[maybe_unused]])
{
    if (msg != nullptr && context != nullptr)
    {
        try
        {
            auto hostObj = static_cast<HostInterface*>(context);
            auto value = hostObj->dhcp4;
            sdbusplus::message_t(msg).append(value);
        }
        catch (const sdbusplus::exception_t& e)
        {
            return sd_bus_error_set(error, e.name(), e.description());
        }
    }
    else
    {
        // The message or context were null
        log<level::ERR>("Unable to service get dhcp4 property callback");
        return -1;
    }

    return 1;
}

int HostInterface::_callback_get_default_gateway(
    sd_bus*, const char*, const char*, const char*, sd_bus_message* msg,
    void* context, sd_bus_error* error [[maybe_unused]])
{
    if (msg != nullptr && context != nullptr)
    {
        try
        {
            auto hostObj = static_cast<HostInterface*>(context);
            auto value = hostObj->defaultGateway;
            sdbusplus::message_t(msg).append(value);
        }
        catch (const sdbusplus::exception_t& e)
        {
            return sd_bus_error_set(error, e.name(), e.description());
        }
    }
    else
    {
        // The message or context were null
        log<level::ERR>(
            "Unable to service get default gateway property callback");
        return -1;
    }

    return 1;
}

int HostInterface::_callback_get_backup_gateway(
    sd_bus*, const char*, const char*, const char*, sd_bus_message* msg,
    void* context, sd_bus_error* error [[maybe_unused]])
{
    if (msg != nullptr && context != nullptr)
    {
        try
        {
            auto hostObj = static_cast<HostInterface*>(context);
            auto value = hostObj->backupGateway;
            sdbusplus::message_t(msg).append(value);
        }
        catch (const sdbusplus::exception_t& e)
        {
            return sd_bus_error_set(error, e.name(), e.description());
        }
    }
    else
    {
        // The message or context were null
        log<level::ERR>(
            "Unable to service get backup gateway property callback");
        return -1;
    }

    return 1;
}

int HostInterface::_callback_get_backup_gateway_mac_address(
    sd_bus*, const char*, const char*, const char*, sd_bus_message* msg,
    void* context, sd_bus_error* error [[maybe_unused]])
{
    if (msg != nullptr && context != nullptr)
    {
        try
        {
            auto hostObj = static_cast<HostInterface*>(context);
            auto value = hostObj->backupGatewayMACAddress;
            sdbusplus::message_t(msg).append(value);
        }
        catch (const sdbusplus::exception_t& e)
        {
            return sd_bus_error_set(error, e.name(), e.description());
        }
    }
    else
    {
        // The message or context were null
        log<level::ERR>(
            "Unable to service get backup gateway mac address property callback");
        return -1;
    }

    return 1;
}

int HostInterface::_callback_get_nic_enabled(
    sd_bus*, const char*, const char*, const char*, sd_bus_message* msg,
    void* context, sd_bus_error* error [[maybe_unused]])
{
    if (msg != nullptr && context != nullptr)
    {
        try
        {
            auto hostObj = static_cast<HostInterface*>(context);
            auto value = hostObj->nicEnabled;
            sdbusplus::message_t(msg).append(value);
        }
        catch (const sdbusplus::exception_t& e)
        {
            return sd_bus_error_set(error, e.name(), e.description());
        }
    }
    else
    {
        // The message or context were null
        log<level::ERR>("Unable to service get nic enabled property callback");
        return -1;
    }

    return 1;
}

const sdbusplus::vtable::vtable_t HostInterface::vtable[] = {
    sdbusplus::vtable::start(),

    sdbusplus::vtable::property("InterfaceName", "s",
                                _callback_get_interface_name,
                                sdbusplus::vtable::property_::emits_change),

    sdbusplus::vtable::property("DHCP4", "b", _callback_get_dhcp4,
                                sdbusplus::vtable::property_::emits_change),

    sdbusplus::vtable::property("DefaultGateway", "s",
                                _callback_get_default_gateway,
                                sdbusplus::vtable::property_::emits_change),

    sdbusplus::vtable::property("BackupGateway", "s",
                                _callback_get_backup_gateway,
                                sdbusplus::vtable::property_::emits_change),

    sdbusplus::vtable::property("BackupGatewayMACAddress", "s",
                                _callback_get_backup_gateway_mac_address,
                                sdbusplus::vtable::property_::emits_change),

    sdbusplus::vtable::property("NICEnabled", "b", _callback_get_nic_enabled,
                                sdbusplus::vtable::property_::emits_change),

    sdbusplus::vtable::end()};

} // namespace hostintf
} // namespace network
} // namespace phosphor
