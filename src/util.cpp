#include "config.h"

#include "util.hpp"

#include "config_parser.hpp"
#include "system_queries.hpp"
#include "types.hpp"

#include <sys/wait.h>
#include <arpa/inet.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <stdplus/numeric/str.hpp>
#include <stdplus/str/buf.hpp>
#include <stdplus/str/cat.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <cctype>
#include <string>
#include <string_view>
#include <unistd.h>
#include <iostream>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <array>
#include <sstream>
#include <vector>
#include <regex>

namespace phosphor
{
namespace network
{

using std::literals::string_view_literals::operator""sv;
using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

namespace internal
{

void executeCommandinChildProcess(stdplus::zstring_view path, char** args)
{
    using namespace std::string_literals;
    pid_t pid = fork();

    if (pid == 0)
    {
        execv(path.c_str(), args);
        exit(255);
    }
    else if (pid < 0)
    {
        auto error = errno;
        lg2::error("Error occurred during fork: {ERRNO}", "ERRNO", error);
        elog<InternalFailure>();
    }
    else if (pid > 0)
    {
        int status;
        while (waitpid(pid, &status, 0) == -1)
        {
            if (errno != EINTR)
            {
                status = -1;
                break;
            }
        }

        if (status < 0)
        {
            stdplus::StrBuf buf;
            stdplus::strAppend(buf, "`"sv, path, "`"sv);
            for (size_t i = 0; args[i] != nullptr; ++i)
            {
                stdplus::strAppend(buf, " `"sv, args[i], "`"sv);
            }
            buf.push_back('\0');
            lg2::error("Unable to execute the command {CMD}: {STATUS}", "CMD",
                       buf.data(), "STATUS", status);
            elog<InternalFailure>();
        }
    }
}

/** @brief Get ignored interfaces from environment */
std::string_view getIgnoredInterfacesEnv()
{
    auto r = std::getenv("IGNORED_INTERFACES");
    if (r == nullptr)
    {
        return "";
    }
    return r;
}

/** @brief Parse the comma separated interface names */
std::unordered_set<std::string_view>
    parseInterfaces(std::string_view interfaces)
{
    std::unordered_set<std::string_view> result;
    while (true)
    {
        auto sep = interfaces.find(',');
        auto interface = interfaces.substr(0, sep);
        while (!interface.empty() && std::isspace(interface.front()))
        {
            interface.remove_prefix(1);
        }
        while (!interface.empty() && std::isspace(interface.back()))
        {
            interface.remove_suffix(1);
        }
        if (!interface.empty())
        {
            result.insert(interface);
        }
        if (sep == interfaces.npos)
        {
            break;
        }
        interfaces = interfaces.substr(sep + 1);
    }
    return result;
}

/** @brief Get the ignored interfaces */
const std::unordered_set<std::string_view>& getIgnoredInterfaces()
{
    static auto ignoredInterfaces = parseInterfaces(getIgnoredInterfacesEnv());
    return ignoredInterfaces;
}

} // namespace internal

int runSystemCommand(const char* cmd, const std::string& params)
{
    std::istringstream iss(params);
    std::vector<std::string> paramList;
    std::string param;

    while (iss >> param) {
        paramList.push_back(param);
    }

    std::vector<const char*> args;
    args.push_back(cmd);
    for (const auto& p : paramList) {
        args.push_back(p.c_str());
    }
    args.push_back(nullptr);

    pid_t pid = fork();
    if (pid == 0)
    {
        execvp(cmd, const_cast<char* const*>(args.data()));

        perror("execvp failed");
        _exit(1);
    }
    else if (pid < 0)
    {
        perror("fork failed");
        return -1;
    }

    int status;
    waitpid(pid, &status, 0);
    return status;
}

std::string runCommandAndStoreLog(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;

    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }

    return result;
}

void executeCommandAndLog(const char* command, const char* logFilePath) {
    try {
        std::string output = runCommandAndStoreLog(command);

        FILE* logFile = fopen(logFilePath, "w");
        if (logFile) {
            fputs(output.c_str(), logFile);
            fclose(logFile);
            std::cout << "Log written to " << logFilePath << std::endl;
        } else {
            std::cerr << "Failed to open log file: " << logFilePath << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

std::optional<std::string> interfaceToUbootEthAddr(std::string_view intf)
{
    constexpr auto pfx = "eth"sv;
    if (!intf.starts_with(pfx))
    {
        return std::nullopt;
    }
    intf.remove_prefix(pfx.size());
    unsigned idx;
    try
    {
        idx = stdplus::StrToInt<10, unsigned>{}(intf);
    }
    catch (...)
    {
        return std::nullopt;
    }
    if (idx == 0)
    {
        return "ethaddr";
    }
    stdplus::ToStrHandle<stdplus::IntToStr<10, unsigned>> tsh;
    return stdplus::strCat("eth"sv, tsh(idx), "addr"sv);
}

static std::optional<DHCPVal> systemdParseDHCP(std::string_view str)
{
    if (config::icaseeq(str, "ipv4"))
    {
        return DHCPVal{.v4 = true, .v6 = false};
    }
    if (config::icaseeq(str, "ipv6"))
    {
        return DHCPVal{.v4 = false, .v6 = true};
    }
    if (auto b = config::parseBool(str); b)
    {
        return DHCPVal{.v4 = *b, .v6 = *b};
    }
    return std::nullopt;
}

inline auto systemdParseLast(const config::Parser& config,
                             std::string_view section, std::string_view key,
                             auto&& fun)
{
    if (!config.getFileExists())
    {}
    else if (auto str = config.map.getLastValueString(section, key);
             str == nullptr)
    {
        lg2::notice(
            "Unable to get the value of {CFG_SEC}[{CFG_KEY}] from {CFG_FILE}",
            "CFG_SEC", section, "CFG_KEY", key, "CFG_FILE",
            config.getFilename());
    }
    else if (auto val = fun(*str); !val)
    {
        lg2::notice(
            "Invalid value of {CFG_SEC}[{CFG_KEY}] from {CFG_FILE}: {CFG_VAL}",
            "CFG_SEC", section, "CFG_KEY", key, "CFG_FILE",
            config.getFilename(), "CFG_VAL", *str);
    }
    else
    {
        return val;
    }
    return decltype(fun(std::string_view{}))(std::nullopt);
}

bool getIPv6AcceptRA(const config::Parser& config)
{
#ifdef ENABLE_IPV6_ACCEPT_RA
    constexpr bool def = true;
#else
    constexpr bool def = false;
#endif
    return systemdParseLast(config, "Network", "IPv6AcceptRA",
                            config::parseBool)
        .value_or(def);
}

bool getIP4Enable(const config::Parser& config)
{
    return systemdParseLast(config, "Network", "IPv4Enable", config::parseBool)
        .value_or(true);
}

bool getIP6Enable(const config::Parser& config)
{
    return systemdParseLast(config, "Network", "IPv6Enable", config::parseBool)
        .value_or(true);
}

bool getIP6StaticRtr(const config::Parser& config)
{
    return systemdParseLast(config, "IPv6Router", "IPv6EnableStaticRtr",
                            config::parseBool)
        .value_or(false);
}

std::tuple<std::string, uint8_t, uint8_t>
    getNCSIValue(const config::Parser& config)
{
    uint8_t channel = systemdParseLast(config, "NCSI", "Channel",
                                       config::parseInt)
                          .value_or(31);
    uint8_t package = systemdParseLast(config, "NCSI", "Package",
                                       config::parseInt)
                          .value_or(8);
    std::string mode = "Auto";
    if (auto str = config.map.getLastValueString("NCSI", "Mode");
        str != nullptr)
    {
        mode = *str;
    }

    return std::make_tuple(mode, package, channel);
}

std::string getIP6StaticRtrAddr(const config::Parser& config,
                                const std::string& Router)
{
    const std::string* ptr = nullptr;

    if (Router.compare("Router1") == 0)
    {
        ptr = config.map.getLastValueString("IPv6Router", "IPv6StaticRtrAddr");
    }
    else if (Router.compare("Router2") == 0)
    {
        ptr = config.map.getLastValueString("IPv6Router",
                                             "IPv6StaticRtr2Addr");
    }
    if (ptr != nullptr)
    {
        return *ptr;
    }

    return "";
}

std::string getMAC(const config::Parser& config)
{
    if (auto str = config.map.getLastValueString("Link", "MACAddress");
        str == nullptr)
    {
        return "";
    }
    else
    {
        return *str;
    }
}

int getIP6StaticRtrPrefix(const config::Parser& config,
                          const std::string& Router)
{
    int val = 0;

    if (Router.compare("Router1") == 0)
    {
        val = systemdParseLast(config, "IPv6Router", "IPv6StaticRtrPrefix",
                               config::parseInt)
                  .value_or(0);
    }
    else if (Router.compare("Router2") == 0)
    {
        val = systemdParseLast(config, "IPv6Router", "IPv6StaticRtr2Prefix",
                               config::parseInt)
                  .value_or(0);
    }

    return val;
}

std::optional<std::tuple<bool, std::string, int>>
    getPHYInfo(const config::Parser& config)
{
    if (config.getFileExists())
    {
        try
        {
            auto autoNeg = systemdParseLast(config, "Link", "AutoNeg",
                                            config::parseBool);
            if (!autoNeg.has_value() || autoNeg.value())
            {
                return std::nullopt;
            }
            const std::string* ptr = config.map.getLastValueString("Link",
                                                                "Duplex");
            if(!ptr) return std::nullopt;

            std::string duplex = *ptr;

            int speed = systemdParseLast(config, "Link", "Speed",
                                         config::parseInt)
                            .value_or(-1);
            return std::make_tuple(autoNeg.value(), duplex, speed);
        }
        catch (const std::exception& e)
        {
            return std::nullopt;
        }
    }
    else
    {
        return std::nullopt;
    }
}

std::string getIP6Gateway(const config::Parser& config)
{
    if (auto str = config.map.getLastValueString("Network", "Gateway");
        str == nullptr)
    {
        return "";
    }
    else
    {
        return *str;
    }
}

DHCPVal getDHCPValue(const config::Parser& config)
{
    return systemdParseLast(config, "Network", "DHCP", systemdParseDHCP)
        .value_or(DHCPVal{.v4 = true, .v6 = true});
}

bool getDHCPProp(const config::Parser& config, DHCPType dhcpType,
                 std::string_view key)
{
    std::string_view type = (dhcpType == DHCPType::v4) ? "DHCPv4" : "DHCPv6";

    if (!config.map.contains(type))
    {
        type = "DHCP";
    }

    return systemdParseLast(config, type, key, config::parseBool)
        .value_or(true);
}

bool getArpGarpEnabled(const config::Parser& config, std::string_view section)
{
    return systemdParseLast(config, section, "Enabled", config::parseBool)
        .value_or(false);
}

bool getArpEnabled(const config::Parser& config, std::string_view section)
{
    return systemdParseLast(config, section, "Enabled", config::parseBool)
        .value_or(true);
}

std::string getGarpInterval(const config::Parser& parser)
{
    if (auto str = parser.map.getLastValueString("GARP", "Interval");
        str == nullptr)
    {
        return "2000"; // Default value as 2000
    }
    else
    {
        return *str;
    }
}

std::tuple<std::vector<std::optional<std::string>>,
           std::vector<std::optional<std::string>>>
    getIndexList(const config::Parser& parser)
{
    auto list = parser.map.getValueStrings("Address", "Index");
    std::vector<std::optional<std::string>> ipv4List(IPV4_MAX_NUM);
    std::vector<std::optional<std::string>> ipv6List(IPV6_MAX_NUM);

    for (std::string vv : list)
    {
        bool ipv6 = vv.find(":") == std::string::npos ? false : true;
        auto delimeterIdx = vv.find_first_of("/");
        std::string addr(vv.begin(), vv.begin() + delimeterIdx);
        int idx =
            std::stoi(std::string(vv.begin() + delimeterIdx + 1, vv.end()));
        if (ipv6)
        {
            ipv6List.at(idx) = addr;
        } // if
        else
        {
            ipv4List.at(idx) = addr;
        }
    }

    return std::make_tuple(ipv4List, ipv6List);
}

std::unordered_map<uint32_t, std::string> getDHCPVendorOption(const config::Parser& config, DHCPType dhcpType)
{
    auto list = config.map.getValueStrings(dhcpType == DHCPType::v4 ? "DHCPv4" : "DHCPv6", "SendVendorOption");
    std::unordered_map<uint32_t, std::string> map;
    for (const auto& v : list)
    {
        auto elements = splitStr(v, ":");
        map.insert(std::pair<uint32_t, std::string>(std::stol(elements.at(0)), elements.at(2)));
        // map[e.at(0).c_str()] = e.at(2);

    }

    return std::move(map);
}

std::string getDHCPVendorClassIdentifier(const config::Parser& config)
{
    if (auto str = config.map.getLastValueString("DHCPv4", "VendorClassIdentifier");
        str == nullptr)
    {
        return "";
    }
    else
    {
        return *str;
    }
}

std::vector<std::string> splitStr(std::string line, std::string delimiter)
{
    std::vector<std::string> vec;
    for (auto index = line.find(delimiter); index != std::string::npos;
         index = line.find(delimiter))
    {
        if (index == 0)
        {
            continue;
        } // if
        else
        {
            vec.push_back(line.substr(0, index));
        }
        line = line.substr(index + 1, line.length());
    }

    vec.push_back(line);
    return vec;
}

std::string getIPv4BackupGateway(const config::Parser& config)
{
    if (auto str = config.map.getLastValueString("Route", "BackupGateway");
        str == nullptr)
    {
        return "";
    }
    else
    {
        return *str;
    }
}

std::string getIPv4DefaultGateway(const config::Parser& config)
{
    if (auto str = config.map.getLastValueString("Route", "DefaultGateway");
        str == nullptr)
    {
        return "";
    }
    else
    {
        return *str;
    }
}

namespace ip_address
{

bool in6AddrIetfProtocolAssignment(in6_addr* addr)
{
    return (ntohl(addr->__in6_u.__u6_addr32[0]) >= 0x20010000 &&
            ntohl(addr->__in6_u.__u6_addr32[0]) <= 0x200101ff);
}

bool in6AddrDoc(in6_addr* addr)
{
    return ntohl(addr->__in6_u.__u6_addr32[0]) == 0x20010db8;
}

void isValidIPv4Addr(std::string addr, Type type)
{
    in_addr gateway = stdplus::fromStr<stdplus::In4Addr>(addr);
    isValidIPv4Addr((in_addr*)&gateway, type);
}

void isValidIPv4Addr(in_addr* addr, Type type)
{
    uint8_t ip[4];
    in_addr_t tmp = stdplus::ntoh(addr->s_addr);
    for (int i = 0; i < 4; i++)
    {
        ip[i] = (tmp >> (8 * (3 - i))) & 0xFF;
    } // for

    if (type == Type::GATEWAY4_ADDRESS)
    {
        if (ip[0] == 0)
        {
            throw std::invalid_argument("Gateway starts with 0.");
        } // if
    }     // if
    else if (type == Type::IP4_ADDRESS)
    {
	
        if (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0)
        {
            throw std::invalid_argument("IPv4 address is 0.0.0.0");
        } // if
        uint32_t hostAddr = (ip[0] << 24) | (ip[1] << 16) | (ip[2] << 8) | ip[3];

        if ((hostAddr & 0xFF000000) == 0x00000000) //0.0.0.0 - 0.255.255.255
        {
            throw std::invalid_argument("IPv4 address cannot be in reserved range");
        }
	else if ((hostAddr & 0xFF000000) == 0x7F000000) //127.0.0.0 - 127.255.255.255
        {
            throw std::invalid_argument("IPv4 address cannot be loopback range");
        }
        else if ((hostAddr & 0xFFFF0000) == 0xA9FE0000) //169.254.0.0 - 169.254.255.255
        {
            throw std::invalid_argument("IPv4 address cannot be link-local range");
        }
        else if ((hostAddr & 0xFFFFFF00) == 0xC0000000) //192.0.0.0 - 192.0.0.255
        {
            throw std::invalid_argument("IPv4 address cannot be in reserved range");
        }
        else if ((hostAddr & 0xFFFFFF00) == 0xC0000200) //192.0.2.0 - 192.0.2.255
        {
            throw std::invalid_argument("IPv4 address cannot be in documentation range");
        }
        else if ((hostAddr & 0xFFFE0000) == 0xC6120000) //198.18.0.0 - 198.19.255.255
        {
            throw std::invalid_argument("IPv4 address cannot be in benchmark range");
        }
        else if ((hostAddr & 0xFFFFFF00) == 0xC6336400) //198.51.100.0 - 198.51.100.255
        {
            throw std::invalid_argument("IPv4 address cannot be in documentation range");
        }
        else if ((hostAddr & 0xFFFFFF00) == 0xCB007100) //203.0.113.0 - 203.0.113.255
        {
            throw std::invalid_argument("IPv4 address cannot be in documentation range");
	}
        else if ((hostAddr & 0xF0000000) == 0xE0000000) //224.0.0.0 - 239.255.255.255
	{
            throw std::invalid_argument("IPv4 address cannot be multicast range");
        }
        else if ((hostAddr & 0xF0000000) == 0xF0000000) //240.0.0.0 - 255.255.255.255
        {
            throw std::invalid_argument("IPv4 address cannot be in reserved range");
        }
        std::string addrStr = inet_ntoa(*addr);
        std::regex ipv4Pattern(R"(^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$)");
        std::smatch match;
        if (!std::regex_match(addrStr, match, ipv4Pattern))
        {
            throw std::invalid_argument("Invalid IPv4 address format");
        }
        for (int i = 1; i <= 4; i++)
        {
            std::string octetStr = match[i];
            if (octetStr.empty())
            {
                throw std::invalid_argument("Invalid IPv4 address");
            }
            if (octetStr.length() > 1 && octetStr[0] == '0')
            {
                throw std::invalid_argument("Invalid IPv4 address, cannot have leading zeros");
            }
            int octet = std::stoi(octetStr);
            if (octet < 0 || octet > 255)
            {
                throw std::invalid_argument("Invalid IPv4 address given. Out of range (0-255)");
            }
        }
    }     // else if
}

void isValidIPv6Addr(std::string addr, Type type)
{
    in6_addr address = stdplus::fromStr<stdplus::In6Addr>(addr);
    isValidIPv6Addr((in6_addr*)&address, type);
}

void isValidIPv6Addr(in6_addr* addr, Type type)
{
    std::string strType{"Gateway"};
    if (type == Type::IP6_ADDRESS)
    {
        strType = "IPv6";
        if (in6AddrIetfProtocolAssignment(addr))
        {
            throw std::invalid_argument(
                strType + " address is IETF Protocol Assignments.");
        }
        else if (in6AddrDoc(addr))
        {
            throw std::invalid_argument(strType + " address is Documentation.");
        }
        else if (IN6_IS_ADDR_LINKLOCAL(addr))
        {
            throw std::invalid_argument(strType + " address is Link-local.");
        }
    }

    if (IN6_IS_ADDR_LOOPBACK(addr))
    {
        throw std::invalid_argument(strType + " is Loopback.");
    }
    else if (IN6_IS_ADDR_MULTICAST(addr))
    {
        throw std::invalid_argument(strType + " is Multicast.");
    }
    else if (IN6_IS_ADDR_SITELOCAL(addr))
    {
        throw std::invalid_argument(strType + " is Sitelocal.");
    }
    else if (IN6_IS_ADDR_V4MAPPED(addr))
    {
        throw std::invalid_argument(strType + " is V4Mapped.");
    }
    else if (IN6_IS_ADDR_UNSPECIFIED(addr))
    {
        throw std::invalid_argument(strType + " is Unspecified.");
    }
    else if (IN6_IS_ADDR_LINKLOCAL(addr))
    {
        throw std::invalid_argument("IPv6 address cannot be link-local");
    }
    else if ((stdplus::ntoh(*(uint32_t*)addr) & 0xFFFFFFFF) == 0x20010db8)
    {
        throw std::invalid_argument("IPv6 address cannot be in documentation range");
    }
}

void isSameSeries(std::string ipStr, std::string gwStr, uint8_t prefixLength)
{
    auto ip = (stdplus::fromStr<stdplus::In4Addr>(ipStr)).a.s_addr;
    auto gw = (stdplus::fromStr<stdplus::In4Addr>(gwStr)).a.s_addr;
    auto netmask = htobe32(~UINT32_C(0) << (32 - prefixLength));

    if ((ip & netmask) != (gw & netmask))
    {
        throw std::logic_error(
            "Gateway address and IP address aren't in the same subnet.");
    } // if
}

} // namespace ip_address
} // namespace network
} // namespace phosphor
