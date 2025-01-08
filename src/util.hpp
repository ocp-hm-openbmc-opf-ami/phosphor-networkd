#pragma once
#include "types.hpp"

#include <stdplus/raw.hpp>
#include <stdplus/zstring_view.hpp>

#include <unordered_map>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_set>
#include <vector>

constexpr auto IPV4_MAX_NUM = 1;
constexpr auto IPV6_MAX_NUM = 16;

namespace phosphor
{
namespace network
{
namespace config
{
class Parser;
}

constexpr auto arpPrefix = "00-bmc-arpcontrol-";
constexpr auto arpSurffix = ".conf";
// using IntfName = std::string;
// using InterfaceList = std::unordered_set<IntfName>;

namespace ip_address
{
enum class Type
{
    GATEWAY4_ADDRESS,
    GATEWAY6_ADDRESS,
    IP4_ADDRESS,
    IP6_ADDRESS
};

/** @brief Check if the address is valid or not
 *  @param[in] addr - The IPv4 address
 *  @param[in] type - What type needed to be checked
 */
void isValidIPv4Addr(std::string addr, Type type);

/** @brief Check if the address is valid or not
 *  @param[in] addr - The IPv6 address
 *  @param[in] type - What type needed to be checked
 */
void isValidIPv6Addr(std::string addr, Type type);

/** @brief Check if the address is valid or not
 *  @param[in] addr - The IPv4 address
 *  @param[in] type - What type needed to be checked
 */
void isValidIPv4Addr(in_addr* addr, Type type);

/** @brief Check if the address is valid or not
 *  @param[in] addr - The IPv6 address
 *  @param[in] type - What type needed to be checked
 */
void isValidIPv6Addr(in6_addr* addr, Type Type);

/** @brief Check if the IPv4 address and default gateway are in the same series
 *  @param[in] ipAddr - The IPv4 address
 *  @param[in] gateway - The IPv4 default gateway address
 *  @param[in] prefixLength - The prefix length of IPv4
 */
void isSameSeries(std::string ipAddr, std::string gateway,
                  uint8_t prefixLength);

} // namespace ip_address

/* @brief converts a sockaddr for the specified address family into
 *        a type_safe InAddrAny.
 * @param[in] family - The address family of the buf
 * @param[in] buf - The network byte order address
 */
constexpr stdplus::InAnyAddr addrFromBuf(int family, std::string_view buf)
{
    switch (family)
    {
        case AF_INET:
            return stdplus::raw::copyFromStrict<stdplus::In4Addr>(buf);
        case AF_INET6:
            return stdplus::raw::copyFromStrict<stdplus::In6Addr>(buf);
    }
    throw std::invalid_argument("Unrecognized family");
}

/** @brief Converts the interface name into a u-boot environment
 *         variable that would hold its ethernet address.
 *
 *  @param[in] intf - interface name
 *  @return The name of th environment key
 */
std::optional<std::string> interfaceToUbootEthAddr(std::string_view intf);

/** @brief read the IPv6AcceptRA value from the configuration file
 *  @param[in] config - The parsed configuration.
 */
bool getIPv6AcceptRA(const config::Parser& config);

/** @brief read the IPv6AcceptRA value from the configuration file
 *  @param[in] config - The parsed configuration.
 */
bool getIP6StaticRtr(const config::Parser& config);

std::string getIP6StaticRtrAddr(const config::Parser& config,
                                const std::string& Router);

int getIP6StaticRtrPrefix(const config::Parser& config,
                          const std::string& Router);

std::tuple<std::string, uint8_t, uint8_t>
    getNCSIValue(const config::Parser& config);

/** @brief read the IPv4Enable value from the configuration file
 *  @param[in] config - The parsed configuration.
 */
bool getIP4Enable(const config::Parser& config);

/** @brief read the IPv6Enable value from the configuration file
 *  @param[in] config - The parsed configuration.
 */
bool getIP6Enable(const config::Parser& config);

/** @brief read the Index of IP address from the configuration file
 *  @param[in] config - The parsed configuration.
 */
std::tuple<std::vector<std::optional<std::string>>,
           std::vector<std::optional<std::string>>>
    getIndexList(const config::Parser& parser);

/** @brief read the DHCP value from the configuration file
 *  @param[in] config - The parsed configuration.
 */
struct DHCPVal
{
    bool v4, v6;
};

enum class DHCPType
{
    v4,
    v6
};

DHCPVal getDHCPValue(const config::Parser& config);

/** @brief Read a boolean DHCP property from a conf file
 *  @param[in] config - The parsed configuration.
 *  @param[in] nwType - The network type.
 *  @param[in] key - The property name.
 */
bool getDHCPProp(const config::Parser& config, DHCPType dhcpType,
                 std::string_view key);

std::optional<std::tuple<bool, std::string, int>>
    getPHYInfo(const config::Parser& config);

bool getArpGarpEnabled(const config::Parser& config, std::string_view section);
std::string getGarpInterval(const config::Parser& config);

bool getArpEnabled(const config::Parser& config, std::string_view section);

std::string getIPv4BackupGateway(const config::Parser& config);

std::string getIPv4DefaultGateway(const config::Parser& config);

std::string getMAC(const config::Parser& config);

std::unordered_map<uint32_t, std::string> getDHCPVendorOption(const config::Parser& config, DHCPType dhcpType);

std::string getDHCPVendorClassIdentifier(const config::Parser& config);
/** @brief Get all the interfaces from the system.
 *  @returns list of interface names.
 */
// InterfaceList getInterfaces();

namespace internal
{

/* @brief runs the given command in child process.
 * @param[in] path - path of the binary file which needs to be execeuted.
 * @param[in] args - arguments of the command.
 */
void executeCommandinChildProcess(stdplus::zstring_view path, char** args);

/** @brief Get ignored interfaces from environment */
std::string_view getIgnoredInterfacesEnv();

/** @brief Parse the comma separated interface names */
std::unordered_set<std::string_view>
    parseInterfaces(std::string_view interfaces);

/** @brief Get the ignored interfaces */
const std::unordered_set<std::string_view>& getIgnoredInterfaces();

} // namespace internal

/* @brief runs the given command in child process.
 * @param[in] path -path of the binary file which needs to be execeuted.
 * @param[in] tArgs - arguments of the command.
 */
template <typename... ArgTypes>
void execute(stdplus::zstring_view path, ArgTypes&&... tArgs)
{
    using expandType = char*[];

    expandType args = {const_cast<char*>(tArgs)..., nullptr};

    internal::executeCommandinChildProcess(path, args);
}

/* @Split string into serveral tokens by delimeter
 * @param[in] line - line to be splitted
 * @param[in] delimiter
 * @returns list of tokens
 */
std::vector<std::string> splitStr(std::string line, std::string delimiter);

/** @brief Use exec instead of system call to run command */
int runSystemCommand(const char* cmd, const std::string& params);

std::string runCommandAndStoreLog(const char* cmd);

void executeCommandAndLog(const char* command, const char* logFilePath);

} // namespace network

} // namespace phosphor
