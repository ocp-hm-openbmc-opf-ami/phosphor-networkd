#include <arpa/inet.h>

#include <cstring>
#include <fstream>
#include <vector>

#define MACLEN 6

namespace racfg6
{
using namespace std;

class route
{
  public:
    struct racfg
    {
        uint8_t gateway6[INET6_ADDRSTRLEN] = {0};
        uint8_t prefix[INET6_ADDRSTRLEN] = {0};
        uint8_t prefixlen = 0;
        uint8_t gateway6MAC[MACLEN] = {0};
        void reset()
        {
            memset(gateway6, 0, sizeof(gateway6));
            memset(prefix, 0, sizeof(prefix));
            memset(gateway6MAC, 0, sizeof(gateway6MAC));
            prefixlen = 0;
        }
    };

    route(std::string iface)
    {
        IPv6DynamicRouterInfo(iface);
    }

    const std::vector<racfg>& getIPv6DynamicRouterInfo() const
    {
        return raCfg6;
    }

  private:
    const char* Filename = "/proc/net/ipv6_route_prefix_info";
    std::vector<racfg> raCfg6;

    void mac_pton(std::string macStr, uint8_t* mac)
    {
        uint8_t MACAddress[6] = {0};

        size_t pos = macStr.find(":");
        uint8_t index = 0;
        while (pos != -1)
        {
            MACAddress[index++] = std::stoi(macStr.substr(0, pos), 0, 16);
            macStr.erase(macStr.begin(), macStr.begin() + pos + 1);
            pos = macStr.find(":");
        }

        MACAddress[index] = std::stoi(macStr, 0, 16);
        memcpy(mac, MACAddress, sizeof(MACAddress));
    }

    void IPv6DynamicRouterInfo(std::string& iface)
    {
        ifstream file;

        file.open(Filename, ios::in);
        if (!file.is_open())
        {
            return;
        }

        std::string line;
        std::vector<std::string> data;
        racfg routeInfo;
        while (file.good())
        {
            std::getline(file, line);
            if (line.empty())
            {
                continue;
            }
            std::string delim = " ";

            size_t pos = line.find(delim);

            while (pos != -1)
            {
                data.push_back(line.substr(0, pos));
                line.erase(line.begin(), line.begin() + pos + 1);
                pos = line.find(delim);
            }

            if (line.compare(iface) != 0)
            {
                data.clear();
                continue;
            }

            /*Gateway IPv6*/
            if (inet_pton(AF_INET6, data.front().c_str(), routeInfo.gateway6) <
                0)
            {
                perror("inet_pton failed ");
            }
            data.erase(data.begin());

            /*Prefix*/
            if (inet_pton(AF_INET6, data.front().c_str(), routeInfo.prefix) < 0)
            {
                perror("inet_pton failed ");
            }

            data.erase((data.begin()));

            /*Prefix Length*/
            routeInfo.prefixlen =
                static_cast<uint8_t>(std::stoul(data.front(), 0, 10));
            data.erase((data.begin()));

            /*Gateway6MAC*/
            mac_pton(data.front().c_str(), routeInfo.gateway6MAC);
            data.erase((data.begin()));

            raCfg6.push_back(routeInfo);

            routeInfo.reset();

            data.clear();
        }

        file.close();
    }
};

} // namespace racfg6
