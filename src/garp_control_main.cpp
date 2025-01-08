#include "config.h"

#include "config_parser.hpp"
#include "garp_control.hpp"
#include "util.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>

using namespace phosphor::network;

constexpr char ARPCONTROL_CONF_DIR[] = "/etc/arpcontrol";
// constexpr auto arpPrefix = "00-bmc-arpcontrol-";
// constexpr auto arpSurffix = ".conf";
std::string arpKey = "ARP_Response";
std::string garpKey = "GARP";

namespace arpControlConfig
{
using ServerList = std::vector<std::string>;
namespace fs = std::filesystem;

/** @brief create the ARP Control config parser object
 *  @returns parser object if success or null
 */
bool parser(config::Parser& parser, std::string& fileName)
{
    fs::path confPath = ARPCONTROL_CONF_DIR;
    confPath /= fileName;

    if (!fs::is_regular_file(confPath.string()))
    {
        return false;
    }
    config::Parser arpControl(confPath.string());
    parser = arpControl;

    return true;
}

/** @brief read the Enabled field from ARP Control config
 *  @param[in] parser - parser object
 *  @param[in] key - searching key
 *  @returns value of Enabled field
 */
bool enabled(config::Parser& parser, std::string& key)
{
    ServerList values;
    auto rc = config::ReturnCode::SUCCESS;

    std::tie(rc, values) = parser.getValues(key, "Enabled");
    if (rc == config::ReturnCode::SUCCESS && !values.empty())
    {
        std::transform(values[0].begin(), values[0].end(), values[0].begin(),
                       ::tolower);
        return (values[0] == "true");
    }

    return false;
}

/** @brief read the interval field from ARP Control config
 *  @param[in] parser - parser object
 *  @param[in] key - searching key
 *  @returns value of interval field
 */
unsigned interval(config::Parser& parser, std::string& key)
{
    ServerList servers;
    auto rc = config::ReturnCode::SUCCESS;
    auto interval = 0;

    std::tie(rc, servers) = parser.getValues(key, "Interval");
    if (rc == config::ReturnCode::SUCCESS && !servers.empty())
    {
        std::stringstream garpInterval(servers[0]);
        garpInterval >> interval;
        return interval;
    }

    return interval;
}

} /* namespace arpControlConfig*/

void GARPTask(const std::string& interface, unsigned interval, bool enable)
{
    phosphor::network::garpControl::GARP garp(interface, interval);
    garp.broadcastPacket(enable);
}

int main()
{
    config::Parser arpControlParser;
    phosphor::network::InterfaceList interfaceList =
        phosphor::network::getInterfaces();
    phosphor::network::InterfaceList::iterator it;
    std::vector<std::thread> threads;

    for (it = interfaceList.begin(); it != interfaceList.end(); ++it)
    {
        std::string fileName = arpPrefix + *it + arpSurffix;

        if (!arpControlConfig::parser(arpControlParser, fileName))
            continue;

        auto garpEnabled = getArpGarpEnabled(arpControlParser, "GARP");
        auto garpInt = getGarpInterval(arpControlParser);
        auto garpInterval = strtoul(garpInt.c_str(), nullptr, 10);

        if (garpEnabled)
            threads.push_back(
                std::thread(GARPTask, *it, garpInterval, garpEnabled));
    }

    for (auto& th : threads)
    {
        th.join();
    }

    return 0;
}
