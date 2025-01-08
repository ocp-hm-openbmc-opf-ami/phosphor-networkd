#pragma once

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/if_ether.h>  /* ETH_P_ARP = 0x0806 */
#include <linux/if_packet.h> /* struct sockaddr_ll (see man 7 packet) */
#include <net/if.h>          /* struct ifreq */
#include <netinet/ether.h>
#include <netinet/in.h>      /* IPPROTO_RAW */
#include <netinet/ip.h>      /* IP_MAXPACKET (which is 65535) */
#include <sys/ioctl.h>       /* macro ioctl is defined */
#include <sys/socket.h>      /* needed for socket() */
#include <sys/types.h>       /* needed for socket(), uint8_t, uint16_t */
#include <unistd.h>

#include <stdplus/raw.hpp>

#include <array>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <variant>
#include <vector>

/* Define some constans */
#define ETH_HDRLEN 14  /* Ethernet header length */
#define IP4_HDRLEN 20  /* IPv4 header length */
#define ARP_HDRLEN 28  /* ARP header length */
#define ARP_OP_REPLY 2 /* Taken from <linux/if_arp.h> */
/* General defines */
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define HWTYPE_ETHER 1
#define ETHER_TYPE 2

namespace phosphor
{

namespace network /*namespace network */
{
using IntfName = std::string;
using IPv4Addrs = struct in_addr;
using EthernetHeader = struct ethhdr;

struct AddrInfo
{
    uint8_t addrType;
    IPv4Addrs ipAddress;
};
/* Byte representations for common address types in network byte order */
using InAddrAny = std::variant<struct in_addr, struct in6_addr>;
using AddrList = std::list<AddrInfo>;
using IntfAddrMap = std::map<IntfName, AddrList>;
using InterfaceList = std::set<IntfName>;
using Addr_t = ifaddrs*;

struct AddrDeleter
{
    void operator()(Addr_t ptr) const
    {
        freeifaddrs(ptr);
    }
};

using AddrPtr = std::unique_ptr<ifaddrs, AddrDeleter>;

constexpr auto IPV4_PREFIX =
    "169.254"; /* IPv4 link-local addresses are assigned from address
                 block 169.254.0.0/16 (169.254.0.0 through 169.254.255.255) */
constexpr auto IPV6_PREFIX = "fe80::"; /* IPv6 link-local addresses are assigned
                                          from address block fe80::/10. */

/** @brief retrive the all the interface
 *  @returns list of interface.
 */
InterfaceList getInterfaces();

/** @brief Converts the given interface name into a interface index
 *  @param[in] mac - The interface name
 *  @returns A valid interface index
 */
unsigned ifIndex(const std::string& interfaceName);

namespace ethernetMAC /*namespace ethernetMAC */
{

/** @brief Converts the given mac address into byte form
 *  @param[in] str - The mac address in human readable form
 *  @returns A mac address in network byte order
 *  @throws std::runtime_error for bad mac
 */
ether_addr fromString(const char* str);
inline ether_addr fromString(const std::string& str)
{
    return fromString(str.c_str());
}

/** @brief Converts the given mac address bytes into a string
 *  @param[in] mac - The mac address
 *  @returns A valid mac address string
 */
std::string toString(const ether_addr& mac);

/** @brief get the mac address of the interface.
 *  @return macaddress on success
 */
std::string getMACaddress(const std::string& interfaceName);

} /*namespace ethernetMAC */

namespace ethernetIP /*namespace ethernetIP */
{

/* @brief converts a String representation of the ip into
 *  ip bytes.
 * @param[in] address - The string representation ip address
 * @returns sockaddr representation of the ip.
 */
IPv4Addrs fromString(const std::string& address);

/* @brief converts the ip bytes into a string representation
 * @param[in] ip - input ip byte address to convert.
 * @returns String representation of the ip.
 */
std::string toString(const IPv4Addrs* ip);

/* @brief checks that the given ip address is link local or not.
 * @param[in] address - IP address.
 * @returns true if it is linklocal otherwise false.
 */
bool isLinkLocalIP(const std::string& address);

/** @brief Gets the map of interface and the associated
 *         address.
 * @param[in] interfaceName - Name of Interface.
 *  @returns map of interface and the address.
 */
IntfAddrMap getInterfaceAddrs(std::string& interfaceName);

} /* namespace ethernetIP */

namespace garpControl /* namespace garpControl */
{
// Define a struct for ARP header
typedef struct arp_header ARPHeader;
struct arp_header
{
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_len;
    uint8_t protocol_len;
    uint16_t opcode;
    uint8_t sender_mac[MAC_LENGTH];
    uint8_t sender_ip[IPV4_LENGTH];
    uint8_t target_mac[MAC_LENGTH];
    uint8_t target_ip[IPV4_LENGTH];
};

/** @class GARP
 *  @brief Network Gratuitous-ARP Reply Broadcasting.
 *  @details A concrete implementation for the
 *  GARP Packet Broadcasting API.
 */
class GARP
{
  public:
    GARP() = default;
    GARP(const GARP&) = delete;
    GARP& operator=(const GARP&) = delete;
    GARP(GARP&&) = delete;
    GARP& operator=(GARP&&) = delete;
    ~GARP() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] interfaceName - GARP Broadcasting interface name.
     *  @param[in] interval - GARP interval .
     */
    GARP(const std::string& interfaceName, const int interval);

    /** @brief Broadcast the GARP Packet into the ethernet interface.
     *  @param[in] start - GARP Broadcast start .
     */
    void broadcastPacket(bool start);

  private:
    /** @brief create the ethernet socket(raw socket) and write the GARP
     *         Packet on it.
     *  @returns true if successful or false.
     */
    bool sendPacket();

    /** @brief reads IP address, interface index and MAC address from ethernet
     *  @returns true if successful or false.
     */
    bool getIfaceDetails();

    /** @brief create GARP header
     *  @param[in] arpHdr - GARP Header .
     */
    void GARPHeader(ARPHeader* arpHdr);

    /** @brief create the frame header with GARP header
     *  @param[in] arpHdr - GARP Header .
     *  @param[in] etherhdr - ethernet Frame Header .
     *  @returns total frame length.
     */
    int frameHeader(ARPHeader* arpHdr, uint8_t* ethernetHdr);

    unsigned int replyInterval; /* frequency of reply send */
    unsigned int ifindex;       /* ethernet interface index */
    ether_addr mac;             /* ethernet MAC address */
    IntfAddrMap IPv4Address;    /* IPv4 address list of interface */
    IPv4Addrs ipAddr;           /* ethernet IP address */
    std::string interface;      /* ethernet interface Name */
};

} /* namespace garpControl */

} /* namespace network */
} // namespace phosphor
