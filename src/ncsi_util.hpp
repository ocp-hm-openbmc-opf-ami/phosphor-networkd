#pragma once

#include <cstdint>
#include <span>
#include <tuple>
#include <vector>
namespace phosphor
{
namespace network
{
namespace ncsi
{

/**
 * enum ncsi_nl_channel_attrs - NCSI netlink channel-specific attributes
 *
 * @NCSI_CHANNEL_ATTR_UNSPEC: unspecified attributes to catch errors
 * @NCSI_CHANNEL_ATTR: nested array of channel attributes
 * @NCSI_CHANNEL_ATTR_ID: channel ID
 * @NCSI_CHANNEL_ATTR_VERSION_MAJOR: channel major version number
 * @NCSI_CHANNEL_ATTR_VERSION_MINOR: channel minor version number
 * @NCSI_CHANNEL_ATTR_VERSION_STR: channel version string
 * @NCSI_CHANNEL_ATTR_LINK_STATE: channel link state flags
 * @NCSI_CHANNEL_ATTR_ACTIVE: channels with this flag are in
 *	NCSI_CHANNEL_ACTIVE state
 * @NCSI_CHANNEL_ATTR_FORCED: flag signifying a channel has been set as
 *	preferred
 * @NCSI_CHANNEL_ATTR_VLAN_LIST: nested array of NCSI_CHANNEL_ATTR_VLAN_IDs
 * @NCSI_CHANNEL_ATTR_VLAN_ID: VLAN ID being filtered on this channel
 * @NCSI_CHANNEL_ATTR_FC: Flow Control being set on this channel
 * @NCSI_CHANNEL_ATTR_MAX: highest attribute number
 */
enum ncsi_nl_channel_attrs
{
    NCSI_CHANNEL_ATTR_UNSPEC,
    NCSI_CHANNEL_ATTR,
    NCSI_CHANNEL_ATTR_ID,
    NCSI_CHANNEL_ATTR_VERSION_MAJOR,
    NCSI_CHANNEL_ATTR_VERSION_MINOR,
    NCSI_CHANNEL_ATTR_VERSION_STR,
    NCSI_CHANNEL_ATTR_LINK_STATE,
    NCSI_CHANNEL_ATTR_ACTIVE,
    NCSI_CHANNEL_ATTR_FORCED,
    NCSI_CHANNEL_ATTR_VLAN_LIST,
    NCSI_CHANNEL_ATTR_VLAN_ID,
    NCSI_CHANNEL_ATTR_FC,
    __NCSI_CHANNEL_ATTR_AFTER_LAST,
    NCSI_CHANNEL_ATTR_MAX = __NCSI_CHANNEL_ATTR_AFTER_LAST - 1
};

constexpr auto DEFAULT_VALUE = -1;
constexpr auto NONE = 0;

static std::vector<std::tuple<uint16_t, std::vector<uint16_t>>> pakckageChannel;
static unsigned int linkStatus;

int sendCommand(int ifindex, int package, int channel, int cmd,
                std::span<const unsigned char> payload);

/* @brief  This function will ask underlying NCSI driver
 *         to send an OEM command (command type 0x50) with
 *         the specified payload as the OEM data.
 *         This function talks with the NCSI driver over
 *         netlink messages.
 * @param[in] ifindex - Interface Index.
 * @param[in] package - NCSI Package.
 * @param[in] channel - Channel number with in the package.
 * @param[in] payload - OEM data to send.
 * @returns 0 on success and negative value for failure.
 */
int sendOemCommand(int ifindex, int package, int channel,
                   std::span<const unsigned char> payload);

/* @brief  This function will ask underlying NCSI driver
 *         to set a specific  package or package/channel
 *         combination as the preferred choice.
 *         This function talks with the NCSI driver over
 *         netlink messages.
 * @param[in] ifindex - Interface Index.
 * @param[in] package - NCSI Package.
 * @param[in] channel - Channel number with in the package.
 * @returns 0 on success and negative value for failure.
 */
int setChannel(int ifindex, int package, int channel);

/* @brief  This function will ask underlying NCSI driver
 *         to clear any preferred setting from the given
 *         interface.
 *         This function talks with the NCSI driver over
 *         netlink messages.
 * @param[in] ifindex - Interface Index.
 * @returns 0 on success and negative value for failure.
 */
int clearInterface(int ifindex);

/* @brief  This function is used to dump all the info
 *         of the package and the channels underlying
 *         the package.
 * @param[in] ifindex - Interface Index.
 * @param[in] package - NCSI Package.
 * @returns 0 on success and negative value for failure.
 */
int getInfo(int ifindex, int package);

int getChannelList(
    int ifindex, int package,
    std::vector<std::tuple<uint16_t, std::vector<uint16_t>>>& channelList);

bool deviceAvailable(int ifindex);

bool getLinkStatus(int ifindex);
} // namespace ncsi
} // namespace network
} // namespace phosphor
