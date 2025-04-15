#pragma once
#include "dhcp_configuration.hpp"
#include "dns_updater.hpp"
#include "ethernet_interface.hpp"
#include "firewall_configuration.hpp"
#include "system_configuration.hpp"
#include "types.hpp"
#if ENABLE_BOND_SUPPORT
#include "xyz/openbmc_project/Network/Bond/Create/server.hpp"
#endif
#include "xyz/openbmc_project/Network/VLAN/Create/server.hpp"

#include <function2/function2.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/message/native_types.hpp>
#include <stdplus/pinned.hpp>
#include <stdplus/str/maps.hpp>
#include <stdplus/zstring_view.hpp>
#include <xyz/openbmc_project/Common/FactoryReset/server.hpp>

#include <condition_variable>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace phosphor
{
namespace network
{

namespace fs = std::filesystem;

#if ENABLE_BOND_SUPPORT
using ManagerIface = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Network::VLAN::server::Create,
    sdbusplus::xyz::openbmc_project::Common::server::FactoryReset,
    sdbusplus::xyz::openbmc_project::Network::Bond::server::Create>;
#else
using ManagerIface = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Network::VLAN::server::Create,
    sdbusplus::xyz::openbmc_project::Common::server::FactoryReset>;
#endif

void writeARPControlDefault(const std::string& filename);

/** @class Manager
 *  @brief OpenBMC network manager implementation.
 */
class Manager : public ManagerIface
{
  public:
    Manager(Manager&&) = delete;
    Manager& operator=(Manager&&) = delete;
    ~Manager();

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] reload - The executor for reloading configs
     *  @param[in] objPath - Path to attach at.
     *  @param[in] confDir - Network Configuration directory path.
     */
    Manager(stdplus::PinnedRef<sdbusplus::bus_t> bus,
            stdplus::PinnedRef<DelayedExecutor> reload,
            stdplus::zstring_view objPath,
            const std::filesystem::path& confDir);

    ObjectPath vlan(std::string interfaceName, uint32_t id) override;

#if ENABLE_BOND_SUPPORT
    ObjectPath bond(std::string activeSlave, uint8_t miiMonitor) override;
#endif
    /** @brief write the network conf file with the in-memory objects.
     */
    void writeToConfigurationFile();

    /** @brief Adds a single interface to the interface map */
    void addInterface(const InterfaceInfo& info);
    void removeInterface(const InterfaceInfo& info);

    /** @brief Add / remove an address to the interface or queue */
    void addAddress(const AddressInfo& info);
    void removeAddress(const AddressInfo& info);

    /** @brief Add / remove a neighbor to the interface or queue */
    void addNeighbor(const NeighborInfo& info);
    void removeNeighbor(const NeighborInfo& info);

    /** @brief Add / remove default gateway for interface */
    void addDefGw(unsigned ifidx, stdplus::InAnyAddr addr);
    void removeDefGw(unsigned ifidx, stdplus::InAnyAddr addr);

    void reconfigLink(int ifidx);

    /** @brief gets the network conf directory.
     */
    inline const auto& getConfDir() const
    {
        return confDir;
    }

    /** @brief gets the arp control conf directory.
     */
    fs::path getARPConfDir()
    {
        return arpConfDir;
    }

    /** @brief gets the interface conf directory.
     */
    fs::path getIfaceConfDir()
    {
        return ifaceConfDir;
    }
#if ENABLE_BOND_SUPPORT
    /** @brief gets the Bonding interface conf backup directory.
     */
    inline fs::path getBondingConfBakDir()
    {
        return bondingConfBakDir;
    }
#endif
    bool createDefaultARPControlFiles(bool force);

    /** @brief ARP Control Configuration directory. */
    fs::path arpConfDir;

    /** @brief Interface Configuration directory. */
    fs::path ifaceConfDir;

    /** @brief gets the system conf object.
     *
     */
    inline auto& getSystemConf()
    {
        return *systemConf;
    }

    /** @brief gets the dhcp conf object.
     *
     */
    inline auto& getDHCPConf()
    {
        return *dhcpConf;
    }

    inline auto& getFirewallConf()
    {
        return *firewallConf;
    }

#ifdef NSUPDATE_SUPPORT
    inline auto& getDNSConf()
    {
        return *ddnsConf;
    }
#endif

    /** @brief Arms a timer to tell systemd-network to reload all of the network
     * configurations
     */
    inline void reloadConfigs()
    {
        reload.get().schedule();
    }

    /** @brief Persistent map of EthernetInterface dbus objects and their names
     */
    stdplus::string_umap<std::unique_ptr<EthernetInterface>> interfaces;
    std::unordered_map<unsigned, EthernetInterface*> interfacesByIdx;
    std::unordered_set<unsigned> ignoredIntf;

    /** @brief Adds a hook that runs immediately prior to reloading
     *
     *  @param[in] hook - The hook to execute before reloading
     */
    inline void addReloadPreHook(fu2::unique_function<void()>&& hook)
    {
        reloadPreHooks.push_back(std::move(hook));
    }
    inline void addReloadPostHook(fu2::unique_function<void()>&& hook)
    {
        reloadPostHooks.push_back(std::move(hook));
    }

    /** supported privilege list **/
    std::vector<std::string> supportedPrivList;

    /** @brief initializes the supportedPrivilege List */
    void initSupportedPrivilges();

    /** @brief get the Default Gateway for File
     */
    std::vector<std::string> getGateway6FromFile();

    /** @brief get the Default Gateway for File
     */
    std::vector<std::string> getGatewayFromFile();

    bool initCompleted;

#ifdef AMI_IP_ADVANCED_ROUTING_SUPPORT
    /** @brief Used to notify/wait to exexute advanced-route */
    std::condition_variable advanced_route_cond_var;
#endif

  protected:
    /** @brief Handle to the object used to trigger reloads of networkd. */
    stdplus::PinnedRef<DelayedExecutor> reload;

    /** @brief Persistent sdbusplus DBus bus connection. */
    stdplus::PinnedRef<sdbusplus::bus_t> bus;

    /** @brief BMC network reset - resets network configuration for BMC. */
    void reset() override;

    /** @brief Path of Object. */
    sdbusplus::message::object_path objPath;

    /** @brief pointer to system conf object. */
    std::unique_ptr<SystemConfiguration> systemConf = nullptr;

    /** @brief pointer to dhcp conf object. */
    std::unique_ptr<dhcp::Configuration> dhcpConf = nullptr;

    /** @brief pointer to firewall conf object. */
    std::unique_ptr<firewall::Configuration> firewallConf = nullptr;

#ifdef NSUPDATE_SUPPORT
    /** @brief pointer to ddns conf object. */
    std::unique_ptr<dns::Configuration> ddnsConf = nullptr;
#endif
    /** @brief Network Configuration directory. */
    std::filesystem::path confDir;

    /** @brief sets the network conf directory.
     *  @param[in] dirName - Absolute path of the directory.
     */
    void setConfDir(const fs::path& dir);

    /** @brief Map of interface info for undiscovered interfaces */
    std::unordered_map<unsigned, AllIntfInfo> intfInfo;

    /** @brief Map of enabled interfaces */
    std::unordered_map<unsigned, bool> systemdNetworkdEnabled;
    sdbusplus::bus::match_t systemdNetworkdEnabledMatch;

    /** @brief List of hooks to execute during the next reload */
    std::vector<fu2::unique_function<void()>> reloadPreHooks;
    std::vector<fu2::unique_function<void()>> reloadPostHooks;

    /** @brief Handles the recipt of an adminstrative state string */
    void handleAdminState(std::string_view state, unsigned ifidx);

    /** @brief Creates the interface in the maps */
    void createInterface(const AllIntfInfo& info, bool enabled);

    /** Get the user management service name dynamically **/
    std::string getUserServiceName();

    /** @brief Custom IPTables Rule directory. */
    fs::path customIPTablesDir;

#if ENABLE_BOND_SUPPORT
    /** @brief Bonding Interface Configuration backup directory. */
    fs::path bondingConfBakDir;
#endif
    std::map<std::string, std::unique_ptr<sdbusplus::bus::match_t>> signals;

    std::map<std::string, std::unique_ptr<sdbusplus::bus::match_t>>
        initSignals();

    void registerSignal(sdbusplus::bus::bus& bus);

  private:
#ifdef AMI_IP_ADVANCED_ROUTING_SUPPORT
    std::thread advanced_route_worker;
    void AdvancedRoute();
    std::unique_lock<std::mutex> advanced_route_lock;
    std::mutex advanced_route_mutex;
#endif
};

} // namespace network
} // namespace phosphor
