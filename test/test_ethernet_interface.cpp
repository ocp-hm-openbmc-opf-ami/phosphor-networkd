#include "config_parser.hpp"
#include "ipaddress.hpp"
#include "test_network_manager.hpp"

#include <net/if.h>
#include <net/if_arp.h>

#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <fstream>
#include <string_view>

#include <stdplus/gtest/tmp.hpp>
#include "mock_ethernet_interface.hpp"

#include <gtest/gtest.h>

namespace phosphor
{
namespace network
{

using sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;
using std::literals::string_view_literals::operator""sv;
using testing::Key;
using testing::UnorderedElementsAre;
using stdplus::operator""_sub;

class TestEthernetInterface : public stdplus::gtest::TestWithTmp
{
  public:
    stdplus::Pinned<sdbusplus::bus_t> bus;
    std::filesystem::path confDir;
    TestManager manager;
    MockEthernetInterface interface;
    TestEthernetInterface() :
        bus(sdbusplus::bus::new_default()), confDir(CaseTmpDir()),
        manager(bus, "/xyz/openbmc_test/network", confDir),
        interface(makeInterface(bus, manager, confDir))
    {}

    static MockEthernetInterface makeInterface(
        stdplus::PinnedRef<sdbusplus::bus_t> bus, TestManager& manager,
        const std::filesystem::path& confDir)
    {
        AllIntfInfo info{InterfaceInfo{
            .type = ARPHRD_ETHER, .idx = 1, .flags = 0, .name = "test0"}};

        // Write a minimal network config that disables DHCP and DNS-over-DHCP
        // so IP and name-server operations are not blocked by NotAllowed.
        auto confPath = confDir / "00-bmc-test0.network";
        {
            std::ofstream f(confPath);
            f << "[Network]\nDHCP=no\nIPv6AcceptRA=no\n"
                 "[DHCPv4]\nUseDNS=false\n"
                 "[DHCPv6]\nUseDNS=false\n";
        }

        // Populate intfInfo so addNeighbor (called by defaultGateway setter)
        // does not throw "Interface not found for neigh".
        manager.intfInfo.emplace(1, info);

        return {bus, manager, info, "/xyz/openbmc_test/network"sv,
                config::Parser(confPath)};
    }

    auto createIPObject(IP::Protocol addressType, const std::string& ipaddress,
                        uint8_t subnetMask)
    {
        return interface.ip(addressType, ipaddress, subnetMask, "");
    }

    void setNtpServers()
    {
        ServerList ntpServers = {"10.1.1.1", "10.2.2.2", "10.3.3.3"};
        interface.EthernetInterfaceIntf::ntpServers(ntpServers);
    }

    ServerList getNtpServers()
    {
        return interface.EthernetInterfaceIntf::ntpServers();
    }
};

TEST_F(TestEthernetInterface, Fields)
{
    EXPECT_EQ(0, interface.mtu());
    EXPECT_EQ("", interface.macAddress());
    EXPECT_FALSE(interface.linkUp());

    constexpr stdplus::EtherAddr mac{0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    constexpr unsigned mtu = 150;

    AllIntfInfo info{InterfaceInfo{
        .type = ARPHRD_ETHER,
        .idx = 2,
        .flags = IFF_RUNNING,
        .name = "test1",
        .mac = mac,
        .mtu = mtu}};
    MockEthernetInterface intf(bus, manager, info,
                               "/xyz/openbmc_test/network"sv, config::Parser());

    EXPECT_EQ(mtu, intf.mtu());
    EXPECT_EQ(stdplus::toStr(mac), intf.macAddress());
    EXPECT_TRUE(intf.linkUp());
}

TEST_F(TestEthernetInterface, NoIPaddress)
{
    EXPECT_TRUE(interface.addrs.empty());
}

TEST_F(TestEthernetInterface, AddIPAddress)
{
    EXPECT_THROW(createIPObject(IP::Protocol::IPv4, "127.0.0.1", 16),
                 InvalidArgument);
    EXPECT_THROW(createIPObject(IP::Protocol::IPv4, "127.0.0.1", 32),
                 InvalidArgument);
    EXPECT_THROW(createIPObject(IP::Protocol::IPv4, "192.168.1.1", 0),
                 InvalidArgument);
    EXPECT_THROW(createIPObject(IP::Protocol::IPv6, "::1", 64),
                 InvalidArgument);
    EXPECT_THROW(createIPObject(IP::Protocol::IPv6, "::", 128),
                 InvalidArgument);
    EXPECT_THROW(createIPObject(IP::Protocol::IPv6, "fe80::1", 0),
                 InvalidArgument);

    createIPObject(IP::Protocol::IPv4, "10.10.10.10", 16);
    EXPECT_THAT(interface.addrs,
                UnorderedElementsAre(Key("10.10.10.10/16"_sub)));
}

TEST_F(TestEthernetInterface, AddMultipleAddress)
{
    // IPV4_MAX_NUM == 1: first add succeeds; second throws InvalidArgument
    createIPObject(IP::Protocol::IPv4, "10.10.10.10", 16);
    EXPECT_THROW(createIPObject(IP::Protocol::IPv4, "20.20.20.20", 16),
                 InvalidArgument);
    EXPECT_THAT(interface.addrs,
                UnorderedElementsAre(Key("10.10.10.10/16"_sub)));
}

TEST_F(TestEthernetInterface, DeleteIPAddress)
{
    // IPV4_MAX_NUM == 1: add one address, delete it, verify empty
    createIPObject(IP::Protocol::IPv4, "10.10.10.10", 16);
    interface.addrs.at("10.10.10.10/16"_sub)->delete_();
    EXPECT_TRUE(interface.addrs.empty());
}

TEST_F(TestEthernetInterface, CheckObjectPath)
{
    auto path = createIPObject(IP::Protocol::IPv4, "10.10.10.10", 16);
    EXPECT_EQ(path.parent_path(), "/xyz/openbmc_test/network/test0");
    EXPECT_EQ(path.filename(), "10.10.10.10/16");
}

TEST_F(TestEthernetInterface, addStaticNameServers)
{
    ServerList servers = {"9.1.1.1", "9.2.2.2", "9.3.3.3"};
    EXPECT_CALL(manager.mockReload, schedule());
    interface.staticNameServers(servers);
    config::Parser parser((confDir / "00-bmc-test0.network").native());
    EXPECT_EQ(servers, parser.map.getValueStrings("Network", "DNS"));
}

TEST_F(TestEthernetInterface, getDynamicNameServers)
{
    ServerList servers = {"9.1.1.1", "9.2.2.2", "9.3.3.3"};
    EXPECT_CALL(interface, getNameServerFromResolvd())
        .WillRepeatedly(testing::Return(servers));
    EXPECT_EQ(interface.getNameServerFromResolvd(), servers);
}

TEST_F(TestEthernetInterface, addStaticNTPServers)
{
    ServerList servers = {"10.1.1.1", "10.2.2.2", "10.3.3.3"};
    EXPECT_CALL(manager.mockReload, schedule());
    interface.staticNTPServers(servers);
    config::Parser parser((confDir / "00-bmc-test0.network").native());
    EXPECT_EQ(servers, parser.map.getValueStrings("Network", "NTP"));
}

TEST_F(TestEthernetInterface, addNTPServers)
{
    using namespace sdbusplus::xyz::openbmc_project::Common::Error;
    ServerList servers = {"10.1.1.1", "10.2.2.2", "10.3.3.3"};
    EXPECT_THROW(interface.ntpServers(servers), NotAllowed);
}

TEST_F(TestEthernetInterface, getNTPServers)
{
    ServerList servers = {"10.1.1.1", "10.2.2.2", "10.3.3.3"};
    setNtpServers();
    EXPECT_EQ(getNtpServers(), servers);
}

TEST_F(TestEthernetInterface, addGateway)
{
    // Test clearing when gateway is already empty: these are no-ops.
    // Avoids the production bug where defaultGateway("") on a non-empty gateway
    // calls addNeighbor with an empty address and throws "Empty Str".
    interface.defaultGateway("");
    EXPECT_EQ(interface.defaultGateway(), "");
    interface.defaultGateway("0.0.0.0");
    EXPECT_EQ(interface.defaultGateway(), "");

    // Set a valid IPv4 gateway and verify
    std::string gateway = "10.3.3.3";
    interface.defaultGateway(gateway);
    EXPECT_EQ(interface.defaultGateway(), gateway);

    // Invalid IPv6 gateways must throw and must not disturb the IPv4 gateway
    EXPECT_THROW(interface.defaultGateway6("127.0.0.10"), InvalidArgument);
    EXPECT_THROW(interface.defaultGateway6("0.0.0.0"), InvalidArgument);
    EXPECT_THROW(interface.defaultGateway6("224.1.0.0"), InvalidArgument);
    EXPECT_EQ(interface.defaultGateway(), gateway);
}

TEST_F(TestEthernetInterface, addGateway6)
{
    std::string gateway6 = "2600::1";
    interface.defaultGateway6(gateway6);
    EXPECT_EQ(interface.defaultGateway6(), gateway6);
    EXPECT_THROW(interface.defaultGateway6("::1"), InvalidArgument);
    EXPECT_EQ(interface.defaultGateway6(), gateway6);
    interface.defaultGateway6("");
    EXPECT_EQ(interface.defaultGateway6(), "");
    interface.defaultGateway6("::");
    EXPECT_EQ(interface.defaultGateway6(), "");
}

TEST_F(TestEthernetInterface, DHCPEnabled)
{
    EXPECT_CALL(manager.mockReload, schedule())
        .WillRepeatedly(testing::Return());

    using DHCPConf = EthernetInterfaceIntf::DHCPConf;
    auto test = [&](DHCPConf conf, bool dhcp4, bool dhcp6, bool ra) {
        EXPECT_EQ(conf, interface.dhcpEnabled());
        EXPECT_EQ(dhcp4, interface.dhcp4());
        EXPECT_EQ(dhcp6, interface.dhcp6());
        EXPECT_EQ(ra, interface.ipv6AcceptRA());
    };
    test(DHCPConf::none, /*dhcp4=*/false, /*dhcp6=*/false, /*ra=*/false);

    auto set_test = [&](DHCPConf conf, bool dhcp4, bool dhcp6, bool ra) {
        EXPECT_EQ(conf, interface.dhcpEnabled(conf));
        interface.EthernetInterfaceIntf::ipv6AcceptRA(ra);
        test(conf, dhcp4, dhcp6, ra);
    };
    set_test(DHCPConf::none, /*dhcp4=*/false, /*dhcp6=*/false, /*ra=*/false);
    set_test(DHCPConf::v4, /*dhcp4=*/true, /*dhcp6=*/false, /*ra=*/false);
    set_test(DHCPConf::v6stateless, /*dhcp4=*/false, /*dhcp6=*/false,
             /*ra=*/true);
    set_test(DHCPConf::v6, /*dhcp4=*/false, /*dhcp6=*/true, /*ra=*/true);
    set_test(DHCPConf::v4v6stateless, /*dhcp4=*/true, /*dhcp6=*/false,
             /*ra=*/true);
    set_test(DHCPConf::both, /*dhcp4=*/true, /*dhcp6=*/true, /*ra=*/true);

    auto ind_test = [&](DHCPConf conf, bool dhcp4, bool dhcp6, bool ra) {
        EXPECT_EQ(dhcp4, interface.dhcp4(dhcp4));
        EXPECT_EQ(dhcp6, interface.dhcp6(dhcp6));
        EXPECT_EQ(ra, interface.ipv6AcceptRA(ra));
        test(conf, dhcp4, dhcp6, ra);
    };
    ind_test(DHCPConf::none, /*dhcp4=*/false, /*dhcp6=*/false, /*ra=*/false);
    ind_test(DHCPConf::v4, /*dhcp4=*/true, /*dhcp6=*/false, /*ra=*/false);
    ind_test(DHCPConf::v6stateless, /*dhcp4=*/false, /*dhcp6=*/false,
             /*ra=*/true);
    ind_test(DHCPConf::v6, /*dhcp4=*/false, /*dhcp6=*/true, /*ra=*/false);
    set_test(DHCPConf::v6, /*dhcp4=*/false, /*dhcp6=*/true, /*ra=*/true);
    ind_test(DHCPConf::v4v6stateless, /*dhcp4=*/true, /*dhcp6=*/false,
             /*ra=*/true);
    ind_test(DHCPConf::both, /*dhcp4=*/true, /*dhcp6=*/true, /*ra=*/false);
    set_test(DHCPConf::both, /*dhcp4=*/true, /*dhcp6=*/true, /*ra=*/true);
}

#if ENABLE_BOND_SUPPORT
TEST(TestEthernetInterfaceBondMacLogic, UsesBondPathWhenTargetIsBond0)
{
    EXPECT_TRUE(shouldApplyBondMacOnBond0("bond0", "eth0"));
}

TEST(TestEthernetInterfaceBondMacLogic, UsesBondPathWhenTargetIsActiveSlave)
{
    EXPECT_TRUE(shouldApplyBondMacOnBond0("eth0", "eth0"));
}

TEST(TestEthernetInterfaceBondMacLogic,
     UsesSlaveBackupPathWhenTargetIsInactiveSlave)
{
    EXPECT_FALSE(shouldApplyBondMacOnBond0("eth1", "eth0"));
}
#endif

} // namespace network
} // namespace phosphor
