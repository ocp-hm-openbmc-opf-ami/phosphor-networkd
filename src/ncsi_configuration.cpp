#include "ncsi_configuration.hpp"

#include "ethernet_interface.hpp"
#include "network_manager.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>

namespace phosphor
{
namespace network
{
namespace ncsi
{

extern std::vector<std::tuple<uint16_t, std::vector<uint16_t>>> pakckageChannel;
using namespace phosphor::logging;
using phosphor::logging::elog;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;
using REASON =
    phosphor::logging::xyz::openbmc_project::Common::NotAllowed::REASON;
using Argument =
    phosphor::logging::xyz::openbmc_project::Common::InvalidArgument;

Configuration::Configuration(sdbusplus::bus_t& bus, std::string_view path,
                             EthernetInterface& eth, NCSIIface::Mode mode,
                             uint8_t package, uint8_t channel) :
    NCSIObj(bus, std::string{path}.c_str(), NCSIObj::action::defer_emit),
    bus(bus), eth(eth)
{
    NCSIIface::mode(mode, true);
    NCSIIface::package(package, true);
    NCSIIface::channel(channel, true);
    if (NCSIIface::mode() == NCSIIface::Mode::Manual)
        setChannel(eth.getIfIdx(), package, channel);

#if NCSI_FLOW_CONTROL
    {
        std::vector<std::tuple<uint16_t, std::vector<uint16_t>>> channelList;
        std::string cmdStr = "14";
        std::vector<unsigned char> data;
        std::string byte = "03";
        try
        {
            data.push_back(stoi(byte, nullptr, 16));
        }
        catch (const std::exception& e)
        {
            log<level::INFO>("Payload invalid.\n");
        }
        getChannelList(eth.getIfIdx(), -1, channelList);
        for (auto v : channelList)
        {
            auto [p, channels] = v;
            for (auto c : channels)
            {
                ncsi::sendCommand(
                    eth.getIfIdx(), p, c, (int)strtol(cmdStr.c_str(), NULL, 16),
                    std::span<const unsigned char>(data.begin(), data.end()));
            }
        }
    }
#endif

    {
        std::vector<std::tuple<uint16_t, std::vector<uint16_t>>> channelList;
        std::vector<unsigned char> payload;
        std::string byte(2, '\0');
#if NCSI_KEEP_PHY_LINK_UP
        std::string payloadStr = "00000157200001";
#else
        std::string payloadStr = "00000157200000";
#endif
        // Parse the payload string (e.g. "000001572100") to byte data
        for (unsigned int i = 1; i < payloadStr.size(); i += 2)
        {
            byte[0] = payloadStr[i - 1];
            byte[1] = payloadStr[i];

            try
            {
                payload.push_back(stoi(byte, nullptr, 16));
            }
            catch (const std::exception& e)
            {
                log<level::INFO>("Payload invalid.\n");
            }
        }
        getChannelList(eth.getIfIdx(), -1, channelList);
        for (auto v : channelList)
        {
            auto [p, channels] = v;
            for (auto c : channels)
            {
                ncsi::sendOemCommand(eth.getIfIdx(), p, c,
                                     std::span<const unsigned char>(
                                         payload.begin(), payload.end()));
            }
        }
    }

    emit_object_added();
}

/** Set value of Mode */
NCSIIface::Mode Configuration::mode(Mode value)
{
    if (!deviceAvailable(eth.getIfIdx()))
    {
        log<level::INFO>("NCSI Interface is not available\n");
        elog<NotAllowed>(REASON("NCSI Interface is not available"));
    }

    if (value != Mode::Auto && value != Mode::Manual)
    {
        log<level::INFO>("Invalid Argument: Mode\n");
        elog<NotAllowed>(REASON("Invalid Argument: Mode"));
    }

    if (value != NCSIIface::mode())
    {
        NCSIIface::mode(value);
        if (value == Mode::Auto)
        {
            NCSIIface::package(MAX_PACKAGE_NUM);
            NCSIIface::channel(MAX_CHANNEL_NUM);
            clearInterface(eth.getIfIdx());
            eth.manager.get().writeToConfigurationFile();
	}
    }
    return value;
}

int16_t Configuration::setPackageChannel(uint8_t package, uint8_t channel)
{
    if (!deviceAvailable(eth.getIfIdx()))
    {
        log<level::INFO>("NCSI Interface is not available\n");
        elog<NotAllowed>(REASON("NCSI Interface is not available"));
    }

    if (NCSIIface::mode() == NCSIIface::Mode::Auto)
    {
        log<level::INFO>("Property update is not allowed in current state\n");
        elog<NotAllowed>(
            REASON("Property update is not allowed in current state"));
    }

    if (package != NCSIIface::package() || channel != NCSIIface::channel())
    {
        clearInterface(eth.getIfIdx());
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (setChannel(eth.getIfIdx(), package, channel) != 0)
            return -1;

        NCSIIface::package(package);
        NCSIIface::channel(channel);
        eth.manager.get().writeToConfigurationFile();
        execute("/bin/systemctl", "systemctl", "restart",
                "systemd-networkd.service");
    }

    return 0;
}

std::vector<std::tuple<uint16_t, std::vector<uint16_t>>>
    Configuration::channelList() const
{
    // Update NCSI Package and Channel list
    std::vector<std::tuple<uint16_t, std::vector<uint16_t>>> pakckageChannel;
    getChannelList(eth.getIfIdx(), -1, pakckageChannel);
    return std::move(pakckageChannel);
    // return {};
}
} // namespace ncsi
} // namespace network
} // namespace phosphor
