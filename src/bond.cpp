#include "bond.hpp"

#include "ethernet_interface.hpp"
#include "network_manager.hpp"
#include "system_queries.hpp"

#include <nlohmann/json.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>

namespace phosphor
{
namespace network
{
using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;
using REASON =
    phosphor::logging::xyz::openbmc_project::Common::NotAllowed::REASON;
using phosphor::logging::elog;

using Argument =
    phosphor::logging::xyz::openbmc_project::Common::InvalidArgument;

constexpr auto IPMI_CHANNEL_CONFIG =
    "/usr/share/ipmi-providers/channel_config.json";

static auto makeObjPath(std::string_view root)
{
    auto ret = sdbusplus::message::object_path(std::string(root));
    return ret;
}

Bond::Bond(sdbusplus::bus_t& bus, std::string_view objRoot,
           EthernetInterface& eth, std::string activeSlave, uint8_t miiMonitor,
           Mode mode) :
    Bond(bus, makeObjPath(objRoot), eth, activeSlave, miiMonitor, mode)
{}

Bond::Bond(sdbusplus::bus_t& bus, sdbusplus::message::object_path objPath,
           EthernetInterface& eth, std::string activeSlave, uint8_t miiMonitor,
           Mode mode) :
    BondObj(bus, objPath.str.c_str(), BondObj::action::defer_emit),
    eth(eth), objPath(std::move(objPath))
{
    BondIntf::activeSlave(activeSlave, true);
    BondIntf::miiMonitor(miiMonitor, true);
    BondIntf::mode(mode, true);
    emit_object_added();
}

void Bond::delete_()
{
    auto intf = eth.interfaceName();
    std::string parentIfName;
    // Remove all configs for the current interface
    const auto& confDir = eth.manager.get().getConfDir();
    std::error_code ec;

    auto ifidx = eth.getIfIdx();
    std::string ipv6StaticRtrAddr{};
    bool ipv4Enable, ipv6Enable, ipv6EnableStaticRtr;

    /**Save Information of Bond0 and later restore*/
    auto it = eth.manager.get().interfaces.find(intf);
    std::map<std::string, std::variant<bool, std::string,
                                       std::vector<std::optional<std::string>>,
                                       uint8_t, uint32_t>>
        map;
    if (it != eth.manager.get().interfaces.end())
    {
        map.emplace("ipv6StaticRtrAddr", it->second->ipv6StaticRtrAddr());
        map.emplace("ipv6EnableStaticRtr", it->second->ipv6EnableStaticRtr());
        it->second->migrateIPIndex(activeSlave());
        map.emplace("ipv4Enable", it->second->ipv4Enable());
        map.emplace("ipv6Enable", it->second->ipv6Enable());
        map.emplace("autoNeg", it->second->autoNeg());
        map.emplace("duplex", static_cast<uint8_t>(it->second->duplex()));
        map.emplace("speed", it->second->speed());
    }
    auto obj = std::move(it->second);
    eth.manager.get().interfaces.erase(it);

    eth.manager.get().writeToConfigurationFile();
    restoreConfiguration(map);
    std::filesystem::remove(config::pathForIntfConf(confDir, intf), ec);
    std::filesystem::remove(config::pathForIntfDev(confDir, intf), ec);
    std::filesystem::remove(
        config::pathForIntfInfo(eth.manager.get().getIfaceConfDir(), intf), ec);

    execute("/bin/systemctl", "systemctl", "stop",
            "phosphor-ipmi-net@bond0.service");
    if (ifidx > 0)
    {
        eth.manager.get().interfacesByIdx.erase(ifidx);
        // We need to forcibly delete the interface as systemd does not
        system::deleteIntf(ifidx);
        // Ignore the interface so the reload doesn't re-query it
        eth.manager.get().ignoredIntf.emplace(ifidx);
    }

    execute("/bin/systemctl", "systemctl", "restart",
            "systemd-networkd.service");

    sleep(3);

    for (auto it = eth.manager.get().interfaces.begin();
         it != eth.manager.get().interfaces.end(); it++)
    {
        if (it->second->interfaceName() != "usb0")
        {
            execute("/bin/systemctl", "systemctl", "restart",
                    fmt::format("phosphor-ipmi-net@{}.service",
                                it->second->interfaceName())
                        .c_str());
        }
    }

    eth.manager.get().reloadConfigs();
}

std::string Bond::activeSlave(std::string activeSlave)
{
    auto it = eth.manager.get().interfaces.find(activeSlave);
    if (it == eth.manager.get().interfaces.end())
    {
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("ActiveSlave"),
                              Argument::ARGUMENT_VALUE(activeSlave.c_str()));
    }
    else if ((activeSlave.compare("bond0") == 0) ||
             (activeSlave.compare("usb0") == 0))
    {
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("ActiveSlave"),
                              Argument::ARGUMENT_VALUE(activeSlave.c_str()));
    }

    if (BondIntf::activeSlave() != activeSlave)
    {
        BondIntf::activeSlave(activeSlave);
        std::system(
            fmt::format(
                "/bin/echo {} > /sys/class/net/bond0/bonding/active_slave",
                activeSlave.c_str())
                .c_str());
    }
    return BondIntf::activeSlave();
}
uint8_t Bond::miiMonitor(uint8_t /*MIIMonitor*/)
{
    elog<NotAllowed>(REASON("Property update is not allowed"));
}
Bond::Mode Bond::mode(Mode /*Bonding Mode*/)
{
    elog<NotAllowed>(REASON("Property update is not allowed"));
}

void Bond::restoreConfiguration(
    std::map<std::string, std::variant<bool, std::string,
                                       std::vector<std::optional<std::string>>,
                                       uint8_t, uint32_t>>
        map)
{
    if (auto it = eth.manager.get().interfaces.find(activeSlave());
        it != eth.manager.get().interfaces.end())
    {
        {
            it->second->EthernetInterfaceIntf::ipv4Enable(
                std::get<bool>(map["ipv4Enable"]), true);
            it->second->EthernetInterfaceIntf::ipv6Enable(
                std::get<bool>(map["ipv6Enable"]), true);
            it->second->EthernetInterfaceIntf::ipv6EnableStaticRtr(
                std::get<bool>(map["ipv6EnableStaticRtr"]), true);
            it->second->EthernetInterfaceIntf::ipv6StaticRtrAddr(
                std::get<std::string>(map["ipv6StaticRtrAddr"]), true);
            it->second->EthernetInterfaceIntf::autoNeg(
                std::get<bool>(map["autoNeg"]), true);
            it->second->EthernetInterfaceIntf::duplex(
                (std::get<uint8_t>(map["duplex"]) == 1
                     ? EthernetInterface::Duplex::full
                     : EthernetInterface::Duplex::half),
                true);
            it->second->EthernetInterfaceIntf::speed(
                std::get<uint32_t>(map["speed"]), true);
        }
        {
            config::Parser config(config::pathForIntfConf(
                eth.manager.get().getConfDir(), "bond0"));
            it->second->loadDomainNames();
            it->second->loadNameServers(config);
            it->second->loadNTPServers(config);
            auto dhcpVal = getDHCPValue(config);
            it->second->EthernetInterfaceIntf::dhcp4(dhcpVal.v4, true);
            it->second->EthernetInterfaceIntf::dhcp6(dhcpVal.v6, true);
            it->second->EthernetInterfaceIntf::ipv6AcceptRA(
                getIPv6AcceptRA(config), true);
        }
    }

    writeBondConfiguration(false);
    for (const auto& dirent : std::filesystem::directory_iterator(
             eth.manager.get().getBondingConfBakDir()))
    {
        std::error_code ec;
        if (dirent.path().filename().generic_string().find(activeSlave()) ==
            std::string::npos)
        {
            std::filesystem::copy_file(
                dirent,
                fmt::format("{}/{}",
                            eth.manager.get().getConfDir().generic_string(),
                            dirent.path().filename().generic_string()),
                fs::copy_options::overwrite_existing, ec);
        }
        std::filesystem::remove(dirent.path(), ec);
    }
}

void Bond::writeBondConfiguration(bool isActive)
{
    std::ofstream ofs;
    std::ifstream ifs, tmpIfs;
    std::string intfName, line, IfaceConfDir, slaveMAC;
    if (isActive)
    {
        ifs.open(config::pathForIntfConf(
            eth.manager.get().getBondingConfBakDir(), BondIntf::activeSlave()));
        if (!ifs.is_open())
        {
            log<level::INFO>(
                "writeBondConfiguration slave configuration file not opened.\n");
        }

        ofs.open(
            config::pathForIntfConf(eth.manager.get().getConfDir(), "bond0"));
        if (!ofs.is_open())
        {
            log<level::INFO>(
                "writeBondConfiguration bond configuration file not opened.\n");
        }

        intfName = "Name=bond0";
    } // if
    else
    {
        ifs.open(
            config::pathForIntfConf(eth.manager.get().getConfDir(), "bond0"));
        if (!ifs.is_open())
        {
            log<level::INFO>(
                "writeBondConfiguration slave configuration file not opened.\n");
        }

        ofs.open(config::pathForIntfConf(eth.manager.get().getConfDir(),
                                         BondIntf::activeSlave()));
        if (!ofs.is_open())
        {
            log<level::INFO>(
                "writeBondConfiguration bond configuration file not opened.\n");
        }

        intfName = fmt::format("Name={}", BondIntf::activeSlave());
    } // else

    while (ifs.peek() != EOF)
    {
        std::getline(ifs, line);
        if (line.starts_with("Name="))
        {
            ofs << intfName << std::endl;
        }
        else
        {
            ofs << line << std::endl;
        }
        line.clear();
    }

    ofs.flush();
    ofs.close();
    ifs.close();

    auto readJsonFile =
        [](const std::string& configFile) -> nlohmann::ordered_json {
        std::ifstream jsonFile(configFile);
        if (!jsonFile.good())
        {
            log<level::ERR>("JSON file not found");
            return nullptr;
        }

        nlohmann::ordered_json data = nullptr;
        try
        {
            data = nlohmann::ordered_json::parse(jsonFile, nullptr, false);
        }
        catch (nlohmann::ordered_json::parse_error& e)
        {
            log<level::ERR>("Corrupted channel config.");
            throw std::runtime_error("Corrupted channel config file");
        }

        return data;
    };

    auto writeJsonFile = [](const std::string& configFile,
                            const nlohmann::ordered_json& jsonData) {
        std::ofstream jsonFile(configFile);
        if (!jsonFile.good())
        {
            log<level::ERR>("JSON file open failed");
            return -1;
        }

        // Write JSON to file
        jsonFile << jsonData.dump(2);

        jsonFile.flush();
        jsonFile.close();
        return 0;
    };

    nlohmann::ordered_json config = readJsonFile(IPMI_CHANNEL_CONFIG);
    config["3"]["name"] = isActive ? "bond0" : "eth0";

    if (writeJsonFile(IPMI_CHANNEL_CONFIG, config) != 0)
    {
        log<level::ERR>("Error in write JSON data to file",
                        entry("FILE=%s", IPMI_CHANNEL_CONFIG));
        elog<InternalFailure>();
    }
}

void Bond::updateMACAddress(std::string macStr)
{
    {
        config::Parser config;
        auto& netdev = config.map["NetDev"].emplace_back();
        netdev["Name"].emplace_back(eth.interfaceName());
        netdev["Kind"].emplace_back("bond");
        netdev["MACAddress"].emplace_back(macStr);
        netdev["MACAddressPolicy"].emplace_back("persistent");
        auto& bond = config.map["Bond"].emplace_back();
        bond["Mode"].emplace_back("active-backup");
        bond["MIIMonitorSec"].emplace_back(fmt::format("{}ms", BondIntf::miiMonitor()));
        config.writeFile(
            config::pathForIntfDev(eth.manager.get().getConfDir(), eth.interfaceName()));
    }

    for (auto it = eth.manager.get().interfaces.begin();
         it != eth.manager.get().interfaces.end(); it++)
    {
	if(it->second->interfaceName() == "bond0")
	{
	    it->second->addrs.clear();
	}

        if((it->second->interfaceName() != "hostusb0") && (it->second->interfaceName() != "bond0"))
        {
                system::setNICUp(it->second->interfaceName(), false);
        }
    }

    system::setNICUp("bond0",false);

    sleep(2);

    execute("/bin/systemctl", "systemctl", "restart",
            "systemd-networkd.service");
}

} // namespace network
} // namespace phosphor
