#include "config.h"

#include "garp_control.hpp"

#include <chrono>
#include <thread>

using namespace std;
using std::this_thread::sleep_for;
namespace phosphor
{
namespace network
{
struct ethernetSocket
{
    ethernetSocket(int domain, int type, int protocol)
    {
        if ((sock = socket(domain, type, protocol)) < 0)
        {
            cout << "socket creation failed" << endl;
        }
    }
    ~ethernetSocket()
    {
        if (sock >= 0)
        {
            close(sock);
        }
    }

    int sock{-1};
};

/** @brief retrive the all the interface
 *  @returns list of interface.
 */
InterfaceList getInterfaces()
{
    InterfaceList interfaces{};
    struct ifaddrs* ifaddr = nullptr;

    if (getifaddrs(&ifaddr) == -1)
    {
        std::cout << "Error occurred during the getifaddrs call" << std::endl;
    }

    AddrPtr ifaddrPtr(ifaddr);
    ifaddr = nullptr;

    for (ifaddrs* ifa = ifaddrPtr.get(); ifa != nullptr; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_flags & IFF_LOOPBACK)
        {
            continue;
        }
        interfaces.emplace(ifa->ifa_name);
    }

    return interfaces;
}

/** @brief Converts the given interface name into a interface index
 *  @param[in] mac - The interface name
 *  @returns A valid interface index
 */
unsigned ifIndex(const std::string& interfaceName)
{
    unsigned idx = if_nametoindex(interfaceName.c_str());
    if (idx == 0)
    {
        throw std::system_error(errno, std::generic_category(),
                                "if_nametoindex");
    }

    return idx;
}

namespace ethernetMAC
{
/** @brief Converts the given mac address into byte form
 *  @param[in] str - The mac address in human readable form
 *  @returns A mac address in network byte order
 *  @throws std::runtime_error for bad mac
 */
ether_addr fromString(const char* str)
{
    struct ether_addr* mac = ether_aton(str);
    if (mac == nullptr)
    {
        throw std::runtime_error("Invalid mac address string");
    }

    return *mac;
}

/** @brief Converts the given mac address bytes into a string
 *  @param[in] mac - The mac address
 *  @returns A valid mac address string
 */
std::string toString(const ether_addr& mac)
{
    char buf[18] = {0};
    snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac.ether_addr_octet[0],
             mac.ether_addr_octet[1], mac.ether_addr_octet[2],
             mac.ether_addr_octet[3], mac.ether_addr_octet[4],
             mac.ether_addr_octet[5]);
    return buf;
}

/** @brief get the mac address of the interface.
 *  @return macaddress on success
 */
std::string getMACaddress(const std::string& interfaceName)
{
    ethernetSocket eifSocket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    if (eifSocket.sock < 0)
        return nullptr;

    ifreq ifr{0};
    std::strncpy(ifr.ifr_name, interfaceName.c_str(), IFNAMSIZ - 1);
    if (ioctl(eifSocket.sock, SIOCGIFHWADDR, &ifr) != 0)
    {
        cout << "ioctl failed for SIOCGIFHWADDR" << endl;
        return nullptr;
    }

    static_assert(sizeof(ifr.ifr_hwaddr.sa_data) >= sizeof(ether_addr));
    std::string_view hwaddr(reinterpret_cast<char*>(ifr.ifr_hwaddr.sa_data),
                            sizeof(ifr.ifr_hwaddr.sa_data));
    return toString(stdplus::raw::copyFrom<ether_addr>(hwaddr));
}

} /*namespace ethernetMAC */

namespace ethernetIP
{
/* @brief converts a String representation of the ip into
 *  ip bytes.
 * @param[in] address - The string representation ip address
 * @returns sockaddr representation of the ip.
 */
IPv4Addrs fromString(const std::string& address)
{
    struct sockaddr_in sa
    {
        0
    };
    int ret = inet_pton(AF_INET, address.c_str(), &(sa.sin_addr));
    if (ret != 1)
    {
        throw std::runtime_error("Invalid IP address string");
    }

    return sa.sin_addr;
}

/* @brief converts the ip bytes into a string representation
 * @param[in] ip - input ip byte address to convert.
 * @returns String representation of the ip.
 */
std::string toString(const IPv4Addrs* ip)
{
    char ipaddress[INET_ADDRSTRLEN];
    auto ret = inet_ntop(AF_INET, ip, ipaddress, INET_ADDRSTRLEN);
    if (ret == nullptr)
    {
        throw std::runtime_error("Invalid IP address string");
    }

    return ipaddress;
}

/* @brief checks that the given ip address is link local or not.
 * @param[in] address - IP address.
 * @returns true if it is linklocal otherwise false.
 */
bool isLinkLocalIP(const std::string& address)
{
    return address.find(IPV4_PREFIX) == 0 || address.find(IPV6_PREFIX) == 0;
}

/** @brief Gets the map of interface and the associated
 *         address.
 *  @returns map of interface and the address.
 */
IntfAddrMap getIPaddrs(std::string& interfaceName)
{
    IntfAddrMap intfMap{};
    struct ifaddrs* ifaddr = nullptr;

    /* attempt to fill struct with ifaddrs */
    if (getifaddrs(&ifaddr) == -1)
    {
        cout << "Error occurred during the getifaddrs call" << endl;
        return intfMap;
    }

    AddrPtr ifaddrPtr(ifaddr);
    ifaddr = nullptr;
    std::string intfName{};

    for (ifaddrs* ifa = ifaddrPtr.get(); ifa != nullptr; ifa = ifa->ifa_next)
    {
        /* walk interfaces */
        if (ifa->ifa_addr == nullptr)
        {
            continue;
        }

        /* get only INET interfaces not ipv6 */
        if (ifa->ifa_addr->sa_family == AF_INET)
        {
            /* if loopback, or not running ignore */
            if ((ifa->ifa_flags & IFF_LOOPBACK) ||
                !(ifa->ifa_flags & IFF_RUNNING))
            {
                continue;
            }
            intfName = ifa->ifa_name;

            if (intfName == interfaceName)
            {
                AddrInfo info{};
                info.addrType = ifa->ifa_addr->sa_family;
                info.ipAddress =
                    ((struct sockaddr_in*)(ifa->ifa_addr))->sin_addr;
                intfMap[intfName].push_back(info);
            }
        }
    }

    return intfMap;
}
} /*namespace ethernetIP */

namespace garpControl
{
/** @brief Constructor to put object onto bus at a dbus path.
 *  @param[in] interfaceName - GARP Broadcasting interface name.
 *  @param[in] interval - GARP interval .
 */
GARP::GARP(const std::string& interfaceName, const int interval)
{
    this->interface = interfaceName;
    this->replyInterval = interval;
}

/** @brief Broadcast the GARP Packet into the ethernet interface.
 *  @param[in] start - GARP Broadcast start .
 */
void GARP::broadcastPacket(bool start)
{
    /* Main Loop*/
    while (start)
    {
        if (!getIfaceDetails())
            continue;

        auto ipAddrs = this->IPv4Address[interface];

        for (auto& addr : ipAddrs)
        {
            if (!ethernetIP::isLinkLocalIP(
                    ethernetIP::toString(&addr.ipAddress)))
            {
                this->ipAddr = addr.ipAddress;
                if (!sendPacket())
                {
                    cout << " Unable to Broadcaste GARP in "
                         << interface << " IP: "
                         << ethernetIP::toString(&addr.ipAddress) << endl;
                }
            }
        }
        sleep_for(std::chrono::milliseconds(this->replyInterval));
    }
}

/** @brief create the ethernet socket(raw socket) and write the GARP
 *         Packet on it.
 *  @returns true if successful or false.
 */
bool GARP::sendPacket()
{
    int frameLength, bytes;
    uint8_t ethernetHdr[IP_MAXPACKET];
    struct sockaddr_ll device;
    ARPHeader arpHdr{0};

    /*Fill out sockaddr_ll */
    device.sll_family = AF_PACKET;
    device.sll_ifindex = ifindex;
    memset(device.sll_addr, 0x00, MAC_LENGTH * sizeof(uint8_t));
    memcpy(device.sll_addr, mac.ether_addr_octet, MAC_LENGTH * sizeof(uint8_t));
    device.sll_halen = htons(MAC_LENGTH);

    GARPHeader(&arpHdr);
    frameLength = frameHeader(&arpHdr, ethernetHdr);

    /* raw socket descriptor  */
    ethernetSocket eifSocket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (eifSocket.sock < 0)
        return false;

    /* Send ethernet frame to socket. */
    if ((bytes = sendto(eifSocket.sock, ethernetHdr, frameLength, 0,
                        (struct sockaddr*)&device, sizeof(device))) <= 0)
    {
        return false;
    }

    return true;
}

/** @brief reads IP address, interface index and MAC address from ethernet
 *  @returns true if successful or false.
 */
bool GARP::getIfaceDetails()
{
    this->IPv4Address.clear();
    this->IPv4Address = ethernetIP::getIPaddrs(this->interface);
    std::string sourceMAC = ethernetMAC::getMACaddress(this->interface);

    if (sourceMAC.empty() || IPv4Address.empty())
        return false;

    this->mac = ethernetMAC::fromString(sourceMAC);
    this->ifindex = ifIndex(this->interface);

    return true;
}

/** @brief create GARP header
 *  @param[in] arphdr - GARP Header .
 */
void GARP::GARPHeader(ARPHeader* arpHdr)
{
    /* ARP header*/
    arpHdr->hardware_type =
        htons(HWTYPE_ETHER); /* Hardware type (16 bits): 1 for ethernet */
    arpHdr->protocol_type =
        htons(ETH_P_IP);     /* Protocol type (16 bits): 2048 for IP */
    arpHdr->hardware_len = MAC_LENGTH;    /* Hardware address length (8 bits): 6
                                             bytes for MAC address */
    arpHdr->protocol_len = IPV4_LENGTH;   /* Protocol address length (8 bits): 4
                                             bytes for IPv4 address */
    arpHdr->opcode = htons(ARP_OP_REPLY); /* OpCode: 2 for ARP reply */
    memcpy(&arpHdr->sender_mac, mac.ether_addr_octet,
           MAC_LENGTH * sizeof(uint8_t)); /* Sender hardware address (48 bits):
                                             MAC address */
    memset(&arpHdr->target_mac, 0x00,
           MAC_LENGTH *
               sizeof(uint8_t)); /* Target hardware address (48 bits): zero */
    memcpy(&arpHdr->sender_ip, &this->ipAddr,
           IPV4_LENGTH * sizeof(uint8_t)); /* Sender IP address */
    memcpy(&arpHdr->target_ip, &this->ipAddr,
           IPV4_LENGTH * sizeof(uint8_t)); /* Target IP address */
}

/** @brief create the frame header with GARP header
 *  @param[in] arpHdr - GARP Header .
 *  @param[in] ethernetHdr - ethernet Frame Header .
 *  @returns total frame length.
 */
int GARP::frameHeader(ARPHeader* arpHdr, uint8_t* ethernetHdr)
{
    int frameLength = 0;

    /* Fill out ethernet frame header*/
    frameLength = MAC_LENGTH + MAC_LENGTH + ETHER_TYPE +
                  ARP_HDRLEN; /* ethernet header (MAC + MAC + ethernet type)
                                 + ethernet data (ARP header) */
    memset(ethernetHdr, 0xFF,
           MAC_LENGTH * sizeof(uint8_t)); /* Destination MAC addresses */
    memcpy(ethernetHdr + MAC_LENGTH, mac.ether_addr_octet,
           MAC_LENGTH * sizeof(uint8_t)); /* Source MAC addresses */

    /* Next is ethernet type code (ETH_P_ARP for ARP) */
    ethernetHdr[12] = ETH_P_ARP / 256;
    ethernetHdr[13] = ETH_P_ARP % 256;
    /* Next is ethernet frame data (ARP header). */
    memcpy(ethernetHdr + ETH_HDRLEN, arpHdr, ARP_HDRLEN * sizeof(uint8_t));

    return frameLength;
}

} /* namespace garpControl */

} /* namespace network */
} // namespace phosphor
