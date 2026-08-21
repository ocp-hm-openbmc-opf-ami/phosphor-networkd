#include "test_network_manager.hpp"

#include "config_parser.hpp"

#include <net/if_arp.h>

#include <fstream>

#include <sdbusplus/bus.hpp>
#include <stdplus/gtest/tmp.hpp>

#include <filesystem>

#include <gtest/gtest.h>

namespace phosphor
{
namespace network
{

using ::testing::Key;
using ::testing::UnorderedElementsAre;

class TestNetworkManager : public stdplus::gtest::TestWithTmp
{
  protected:
    stdplus::Pinned<sdbusplus::bus_t> bus;
    TestManager manager;
    TestNetworkManager() :
        bus(sdbusplus::bus::new_default()),
        manager(bus, "/xyz/openbmc_test/abc", CaseTmpDir())
    {
        // Reset channel privilege JSON before each test case to prevent state
        // leakage: getChannelPrivilege() writes to /var/channel_intf_data.json
        // during EthernetInterface construction; stale entries from a previous
        // test can leave the file in a state that causes type_error.305.
        if (std::ofstream f("/var/channel_intf_data.json"); f.good())
            f << "{}";
    }

    void deleteVLAN(std::string_view ifname)
    {
        manager.interfaces.find(ifname)->second->vlan->delete_();
    }
};

TEST_F(TestNetworkManager, NoInterface)
{
    EXPECT_TRUE(manager.interfaces.empty());
}

TEST_F(TestNetworkManager, WithSingleInterface)
{
    manager.addInterface(
        {.type = ARPHRD_ETHER, .idx = 2, .flags = 0, .name = "igb1"});
    manager.handleAdminState("managed", 2);

    // Now create the interfaces which will call the mocked getifaddrs
    // which returns the above interface detail.
    EXPECT_THAT(manager.interfaces, UnorderedElementsAre(Key("igb1")));
}

// getifaddrs returns two interfaces.
TEST_F(TestNetworkManager, WithMultipleInterfaces)
{
    manager.addInterface(
        {.type = ARPHRD_ETHER, .idx = 1, .flags = 0, .name = "igb0"});
    manager.handleAdminState("managed", 1);
    manager.handleAdminState("unmanaged", 2);
    manager.addInterface(
        {.type = ARPHRD_ETHER, .idx = 2, .flags = 0, .name = "igb1"});

    EXPECT_THAT(manager.interfaces,
                UnorderedElementsAre(Key("igb0"), Key("igb1")));
}

TEST_F(TestNetworkManager, WithVLAN)
{
    EXPECT_THROW(manager.vlan("", 8000), std::exception);
    EXPECT_THROW(manager.vlan("", 0), std::exception);
    EXPECT_THROW(manager.vlan("eth0", 2), std::exception);

    manager.addInterface(
        {.type = ARPHRD_ETHER, .idx = 1, .flags = 0, .name = "eth0"});
    manager.handleAdminState("managed", 1);
    EXPECT_NO_THROW(manager.vlan("eth0", 2));
    EXPECT_NO_THROW(manager.vlan("eth0", 4094));
    EXPECT_THAT(
        manager.interfaces,
        UnorderedElementsAre(Key("eth0"), Key("eth0.2"), Key("eth0.4094")));
    auto netdev1 = config::pathForIntfDev(CaseTmpDir(), "eth0.2");
    auto netdev2 = config::pathForIntfDev(CaseTmpDir(), "eth0.4094");
    EXPECT_TRUE(std::filesystem::is_regular_file(netdev1));
    EXPECT_TRUE(std::filesystem::is_regular_file(netdev2));

    deleteVLAN("eth0.2");
    EXPECT_THAT(manager.interfaces,
                UnorderedElementsAre(Key("eth0"), Key("eth0.4094")));
    EXPECT_FALSE(std::filesystem::is_regular_file(netdev1));
    EXPECT_TRUE(std::filesystem::is_regular_file(netdev2));

    // Delete the remaining VLAN to stop its monitor thread.
    // EthernetInterface has no destructor to join vlanMonitorThread; leaving
    // the thread running causes std::thread::~thread() on a joinable thread
    // which calls terminate().
    deleteVLAN("eth0.4094");
    EXPECT_THAT(manager.interfaces, UnorderedElementsAre(Key("eth0")));
    EXPECT_FALSE(std::filesystem::is_regular_file(netdev2));
}

} // namespace network
} // namespace phosphor
