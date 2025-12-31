#pragma once

#include "system_configuration.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <stdplus/zstring.hpp>
#include <xyz/openbmc_project/Network/DDNS/server.hpp>
#include <xyz/openbmc_project/State/BMC/server.hpp>

#include <condition_variable>
#include <filesystem>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>

namespace phosphor
{
namespace network
{
namespace dns
{
namespace updater
{

namespace fs = std::filesystem;

constexpr auto RESOLV_CONF = "/etc/resolv.conf";

class Manager; // forward declaration of network manager.

/** @brief Reads DNS entries supplied by DHCP and updates specified file
 *
 *  @param[in] inFile  - File having DNS entries supplied by DHCP
 *  @param[in] outFile - File to write the nameserver entries to
 */
void updateDNSEntries(const fs::path& inFile, const fs::path& outFile);

/** @brief User callback handler invoked by inotify watcher
 *
 *  Needed to enable production and test code so that the right
 *  callback functions could be implemented
 *
 *  @param[in] inFile - File having DNS entries supplied by DHCP
 */
inline void processDNSEntries(const fs::path& inFile)
{
    return updateDNSEntries(inFile, RESOLV_CONF);
}

} // namespace updater

using ddnsIface = sdbusplus::xyz::openbmc_project::Network::server::DDNS;

using Iface = sdbusplus::server::object_t<ddnsIface>;
using IfacesRegisterStatus =
    std::vector<std::tuple<std::string, bool, bool, bool, ddnsIface::Method>>;

enum class DNS_PROGESS
{
    NO_PROGESS = 0,
    IN_PROGESS = 1,
};

class Configuration : Iface
{
  public:
    /* Define all of the basic class operations:
     *     Not allowed:
     *         - Default constructor to avoid nullptrs.
     *         - Copy operations due to internal unique_ptr.
     *         - Move operations due to 'this' being registered as the
     *           'context' with sdbus.
     *     Allowed:
     *         - Destructor.
     */
    Configuration() = delete;
    Configuration(const Configuration&) = delete;
    Configuration& operator=(const Configuration&) = delete;
    Configuration(Configuration&&) = delete;
    Configuration& operator=(Configuration&&) = delete;
    ~Configuration();

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     */
    Configuration(sdbusplus::bus_t& bus, stdplus::const_zstring path,
                  Manager& parent);

    // ========================== Add Method below ==========================

    /** @brief Implementation for DoNsupdate
     *  Restart DNS Service
     *
     *  @return result[int16_t] -
     */
    int16_t doNsupdate() override;

    /** @brief Implementation for SetHostConf
     *  HostName Configuration
     *
     *  @param[in] hostSetting - True for automatic and False for manul
     *  @param[in] hostName - Manully set hostname
     *
     *  @return result[int16_t] -
     */

    /** @brief Implementation for toRegister
     *  Run nsupdate to register
     *
     *  @return result[int16_t] -
     */
    int16_t toRegister() override;
    /** @brief Implementation for toDeregister
     *  Run nsupdate to deregister.
     *
     *  @return result[int16_t] -
     */
    int16_t toDeregister() override;

    /** @brief Implementation for SetHostConf
     *  HostName Configuration
     *
     *  @param[in] hostSetting - True for automatic and False for manul
     *  @param[in] hostName - Manully set hostname
     *
     *  @return result[int16_t] -
     */
    int16_t setHostConf(bool hostSetting, std::string hostName) override;

    /** @brief Implementation for SetInterfacesConf
     *  Interfaces Configuration for DNS
     *
     *  @param[in] interfaceConf - Data 1 - Interface Name Data 2 - Do nsupdate
     * or not Data 4 - Use TSIG Authentication or not Data 5 - To register or
     * deregister
     *
     *  @return result[int16_t] -
     */
    int16_t setInterfacesConf(
        std::vector<std::tuple<std::string, bool, bool, Method>> interfaceConf)
        override;

#if 0
        /** @brief Implementation for SetDomainConf
         *  Domain Configuration
         *
         *  @param[in] dhcp - True for DHCP method and False for static method
         *  @param[in] priority - 1 for IPv4, 2 for IPv6 and 0 for static method
         *  @param[in] domainName - Domain Nameto register DNS server if Domain DHCP is disable
         *
         *  @return result[int16_t] -
         */
        int16_t setDomainConf(bool dhcp,uint8_t priority,std::string domainName) override;
#endif
    /** @brief Implementation for SetDNSServer
     *  DNS Configuration
     *
     *  @param[in] interface - Interface for DNS server
     *  @param[in] servers - DNS Server IPs
     *
     *  @return result[int16_t] -
     */
    int16_t setDNSServer(std::string interface,
                         std::vector<std::string> servers) override;

    /** @brief Implementation for GetDNSServer
     *  DNS Configuration
     *
     *  @param[in] interface - Interface for DNS server
     *
     *  @return result[std::vector<std::string>] -
     */
    std::vector<std::string> getDNSServer(std::string interface) override;

    bool sendNsupdateEnabled(bool value) override;

    void registerSignal(sdbusplus::bus_t& bus);

    std::map<std::string, std::unique_ptr<sdbusplus::bus::match_t>>
        initSignals();

    // ========================== Add Property below ==========================
#if 0
        bool dnsEnabled(bool value) override;
#endif
    /** Set value of useMDNS */
    bool useMDNS(bool value) override;

    std::tuple<bool, std::string> hostConf(
        std::tuple<bool, std::string> value) override;

    std::vector<std::tuple<std::string, bool, bool, ddnsIface::Method>>
        interfacesConf(std::vector<std::tuple<std::string, bool, bool, Method>>
                           value) override;
#if 0
        std::tuple<bool, uint8_t, std::string> domainConf(std::tuple<bool, uint8_t, std::string> value) override;
#endif
    void addInterfaceConf(std::string interface);

    std::queue<std::function<void()>> dnsWorkq;
    std::condition_variable dnsCondVar;

    std::vector<std::string> getDomainName(std::string interface);

    using ddnsIface::hostConf;
    using ddnsIface::interfacesConf;
#if 0
        using ddnsIface::domainConf;
#endif
#if 0
        using ddnsIface::dnsEnabled;
#endif
    using ddnsIface::sendNsupdateEnabled;
    using ddnsIface::setInProgress;

  protected:
    void writeConfigurationFile();
    int16_t updateDNSInfo(bool bakupInfo);
    std::string getRevIPv4(std::string ipv4);
    std::string getRevIPv6(std::string ipv6);
    std::vector<std::tuple<std::string, bool, bool, ddnsIface::Method>>
        preIfaceConf;
    std::tuple<bool, std::string> preHost;
    std::vector<std::tuple<std::string, std::vector<std::string>>> preDomain;
    std::vector<std::tuple<std::string, std::vector<std::string>>> preDns;
    std::vector<std::tuple<std::string, std::vector<std::string>>> preIPAddr;
    bool preUseMDNS;

  private:
    /** @brief sdbusplus DBus bus connection. */
    sdbusplus::bus_t& bus;

    /** @brief Network Manager object. */
    stdplus::PinnedRef<Manager> manager;

    DNS_PROGESS state;
    std::thread dnsWorker;
    std::unique_lock<std::mutex> dnsLock;
    std::mutex dnsMutex;
    void dnsWorkerFunc();
    bool NsupdateEnabledChanged;
}; // class Configuration

} // namespace dns
} // namespace network
} // namespace phosphor
