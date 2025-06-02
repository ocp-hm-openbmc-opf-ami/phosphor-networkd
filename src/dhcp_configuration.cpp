#include "dhcp_configuration.hpp"

#include "config_parser.hpp"
#include "network_manager.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{
using namespace phosphor::logging;
namespace dhcp
{

using namespace phosphor::network;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using NotAllowed = sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;
using NotAllowedArgument = xyz::openbmc_project::Common::NotAllowed;

constexpr auto NETWORK_Service = "xyz.openbmc_project.Network";
#if NSUPDATE_SUPPORT
constexpr auto DNS_OBJ_PATH = "/xyz/openbmc_project/network/dns";
constexpr auto DNS_INTERFACE = "xyz.openbmc_project.Network.DDNS";
#endif

Configuration::Configuration(sdbusplus::bus_t& bus,
                             stdplus::const_zstring objPath,
                             stdplus::PinnedRef<EthernetInterface> parent,
                             DHCPType type) :
    Iface(bus, objPath.c_str(), Iface::action::defer_emit),
    parent(parent)
{
    config::Parser conf(config::pathForIntfConf(
        parent.get().manager.get().getConfDir(), parent.get().interfaceName()));
    ConfigIntf::dnsEnabled(getDHCPProp(conf, type, "UseDNS"), true);
    ConfigIntf::domainEnabled(getDHCPProp(conf, type, "UseDomains"),
                              ConfigIntf::dnsEnabled());
    ConfigIntf::ntpEnabled(getDHCPProp(conf, type, "UseNTP"), true);
    ConfigIntf::hostNameEnabled(getDHCPProp(conf, type, "UseHostname"), true);
    ConfigIntf::sendHostNameEnabled(getDHCPProp(conf, type, "SendHostname"),
                                    true);
    ConfigIntf::vendorClassIdentifier(getDHCPVendorClassIdentifier(conf));
    vendorOptionList = getDHCPVendorOption(conf, type);
    this->type = type;
    signals = initSignals();
    registerSignal(bus);
    emit_object_added();
}

std::map<std::string, std::unique_ptr<sdbusplus::bus::match_t>>
    Configuration::initSignals()
{
    std::map<std::string, std::unique_ptr<sdbusplus::bus::match_t>> mp;
#if 0
    mp["DDNSSignal"] = nullptr;
#endif
    return mp;
}

void Configuration::registerSignal(sdbusplus::bus::bus& bus)
{
#if 0
    for (auto& signal : Configuration::signals) {
        if (signal.second == nullptr && signal.first == "DDNSSignal") {
            signal.second = std::make_unique<sdbusplus::bus::match_t>(
                bus,
                sdbusplus::bus::match::rules::propertiesChanged(DNS_OBJ_PATH, DNS_INTERFACE),
                [&](sdbusplus::message::message& msg) {
                    std::map<std::string, std::variant<std::string, std::vector<std::string>,  bool, std::tuple<bool, uint8_t, std::string>>> props;
                    std::string iface;
                    bool value;
                    msg.read(iface, props);
                    for (const auto& t : props)
                    {
                        if (t.first == "DNSEnabled")
                        {
                            value = std::get<bool>(t.second);
                            dnsEnabled(value);
                            auto [enabled, priority, domainName] = manager.get().getDNSConf().domainConf();
                            if (enabled && dnsEnabled() == true) {
                                domainEnabled(enabled);
                            }
                        }
                    }
                }
            );
        }
    }
#endif
}

bool Configuration::sendHostNameEnabled(bool value)
{
    if (value == sendHostNameEnabled())
    {
        return value;
    }

    auto name = ConfigIntf::sendHostNameEnabled(value);
    parent.get().writeConfigurationFile();
    parent.get().reloadConfigs();
    return name;
}

bool Configuration::hostNameEnabled(bool value)
{
    if (value == hostNameEnabled())
    {
        return value;
    }

    auto name = ConfigIntf::hostNameEnabled(value);
    parent.get().writeConfigurationFile();
    parent.get().reloadConfigs();

    return name;
}

bool Configuration::ntpEnabled(bool value)
{
    if (value == ntpEnabled())
    {
        return value;
    }

    auto ntp = ConfigIntf::ntpEnabled(value);
    parent.get().writeConfigurationFile();
    parent.get().reloadConfigs();

    return ntp;
}

bool Configuration::dnsEnabled(bool value)
{
    if (value == dnsEnabled())
    {
        return value;
    }

    auto dns = ConfigIntf::dnsEnabled(value);
    if (value == false)
    {
        ConfigIntf::domainEnabled(value);
    }
    else
    {
        parent.get().staticNameServers({});
    }
    parent.get().writeConfigurationFile();
    parent.get().reloadConfigs();

    return dns;
}

bool Configuration::domainEnabled(bool value)
{
    if (value == domainEnabled())
    {
        return value;
    }

    auto domain = ConfigIntf::domainEnabled(value);
    if (value)
        parent.get().domainName({});
    parent.get().writeConfigurationFile();
    parent.get().reloadConfigs();

    return domain;
}

std::string Configuration::vendorClassIdentifier(std::string value)
{
   if (this->type != DHCPType::v4)
    {
        log<level::ERR>("Vendor Class Identifier only supports in DHCPv4.\n");
        elog<NotAllowed>(NotAllowedArgument::REASON("Vendor Class Identifier only supports in DHCPv4.\n"));
    }
    if (value == Configuration::vendorClassIdentifier())
    {
        return value;
    }

    ConfigIntf::vendorClassIdentifier(value);
    parent.get().writeConfigurationFile();
    parent.get().reloadConfigs();
    return value;
}

int16_t Configuration::setVendorOption(uint32_t option, std::string value)
{
    if (auto it = vendorOptionList.find(option); it != vendorOptionList.end() && it->second == value)
    {
        return 0;
    }

    vendorOptionList[option] = value;
    parent.get().writeConfigurationFile();
    parent.get().reloadConfigs();
    return 0;
}


std::string Configuration::getVendorOption(uint32_t option)
{
    if (vendorOptionList.find(option) == vendorOptionList.end())
    {
        return "";
    }

    return vendorOptionList[option];
}

int16_t Configuration::delVendorOption(uint32_t option)
{
    if (vendorOptionList.find(option) == vendorOptionList.end())
    {
        return -1;
    }

    vendorOptionList.erase(option);
    parent.get().writeConfigurationFile();
    parent.get().reloadConfigs();
    return 0;
}

} // namespace dhcp
} // namespace network
} // namespace phosphor
