#ifndef CDPLAYER_HPP
#define CDPLAYER_HPP

#include <arpa/inet.h>
#include <string>
#include <vector>
#include <iostream>
#include <unordered_map>
#include <stdexcept>
#include <iomanip>
#include <algorithm>

// Class representing CDP Layer
/**
 * @class CDPLayer
 * 
 * @brief Represents a CDP layer in a network packet.
 * 
 * The CDPLayer class provides methods for accessing and parsing CDP data from a network packet.
 * It extracts information such as the device ID, port ID, TTL, port description, system name,
 * system description, system capabilities, and management address from the CDP packet.
 * 
 * The CDPLayer class also provides an overloaded operator for outputting CDP layer information.
 */
class CDPLayer {
public:
    // Constructor and Destructor
    CDPLayer(const uint8_t* data, size_t dataLen);
    ~CDPLayer();

    enum CDPTlvType {
        CDP_TLV_TYPE_DEVICE_ID = 0x0001,
        CDP_TLV_TYPE_ADDRESS = 0x0002,
        CDP_TLV_TYPE_PORT_ID = 0x0003,
        CDP_TLV_TYPE_CAPABILITIES = 0x0004,
        CDP_TLV_TYPE_SOFTWARE_VERSION = 0x0005,
        CDP_TLV_TYPE_PLATFORM = 0x0006,
        CDP_TLV_TYPE_IP_PREFIX = 0x0007,
        CDP_TLV_TYPE_VTP_MANAGEMENT_DOMAIN = 0x0009,
        CDP_TLV_TYPE_NATIVE_VLAN = 0x000A,
        CDP_TLV_TYPE_MGMT_ADDRESS = 0x0016,
        CDP_TLV_TYPE_DUPLEX = 0x000B,
        CDP_TLV_TYPE_TRUST_BITMAP = 0x0012,
        CDP_TLV_TYPE_UNTRUSTED_PORT_COS = 0x0013,
        CDP_TLV_TYPE_SYSTEM_NAME = 0x000D,
        CDP_TLV_TYPE_SYSTEM_DESCRIPTION = 0x000E,
        CDP_TLV_TYPE_POWER_CONSUMPTION = 0x0010,
        CDP_TLV_TYPE_POWER_REQUEST = 0x000F
    };

    enum DeviceIdSubtype {
        DEVICE_ID_SUBTYPE_LOCAL = 0x00,
        DEVICE_ID_SUBTYPE_GLOBAL = 0x01
    };

    // Structs for representing CDP components
    struct DeviceId {
        DeviceIdSubtype subtype;
        std::string id;
    };

    struct Address {
        uint16_t protocolType;
        uint16_t protocolLength;
        uint16_t protocol;
        uint16_t addressLength;
        const uint8_t* address;
    };

    struct Addresses {
        std::vector<Address> addresses;
        uint32_t numberOfAddresses;
    };

    enum SystemCapabilities {
        CAPABILITY_ROUTER = 1 << 0,
        CAPABILITY_TRANSPARENT_BRIDGE = 1 << 1,
        CAPABILITY_SOURCE_ROUTE_BRIDGE = 1 << 2,
        CAPABILITY_SWITCH = 1 << 3,
        CAPABILITY_HOST = 1 << 4,
        CAPABILITY_IGMP = 1 << 5,
        CAPABILITY_REPEATER = 1 << 6,
        CAPABILITY_VOIP_PHONE = 1 << 7,
        CAPABILITY_REMOTELY_MANAGED = 1 << 8,
        CAPABILITY_CVTA = 1 << 9,
        CAPABILITY_TWO_PORT_MAC_RELAY = 1 << 10
    };

    struct TLV {
        uint8_t type;
        uint16_t length;
        const uint8_t* value;
    };

    // Public methods for accessing CDP data
    struct CDPLayer::DeviceId getDeviceId() const;
    struct CDPLayer::Addresses getAddresses() const;
    std::string getPortId() const;
    uint32_t getCapabilities() const;
    std::string capabilitiesToString(uint32_t capabilities) const;
    std::string getSoftwareVersion() const;
    std::string getPlatform() const;
    std::string getVTPManagementDomain() const;
    uint16_t getNativeVlan() const;
    uint8_t getDuplex() const;
    uint8_t getTrustBitmap() const;
    uint8_t getUntrustedPortCos() const;
    struct CDPLayer::Addresses getMgmtAddresses() const;
    uint16_t getTTL() const;

    // Overloaded operator for outputting CDP layer information
    friend std::ostream& operator<<(std::ostream& os, const CDPLayer& layer);

private:
    // Data members for CDP processing
    const uint8_t* rawData;
    size_t rawDataLength;

    // Helper functions
    void parseTLVs();
    TLV getTLV(uint8_t type) const;

    // Data structures for storing parsed TLVs
    std::vector<TLV> tlvs;

    const std::unordered_map<uint32_t, std::string> capabilitiesMap = {
        {CAPABILITY_ROUTER, "Router"},
        {CAPABILITY_TRANSPARENT_BRIDGE, "Transparent Bridge"},
        {CAPABILITY_SOURCE_ROUTE_BRIDGE, "Source Route Bridge"},
        {CAPABILITY_SWITCH, "Switch"},
        {CAPABILITY_HOST, "Host"},
        {CAPABILITY_IGMP, "IGMP"},
        {CAPABILITY_REPEATER, "Repeater"},
        {CAPABILITY_VOIP_PHONE, "VoIP Phone"},
        {CAPABILITY_REMOTELY_MANAGED, "Remotely Managed"},
        {CAPABILITY_CVTA, "CVTA"},
        {CAPABILITY_TWO_PORT_MAC_RELAY, "Two Port MAC Relay"}
    };
};

std::string toHexString(const uint8_t* data, size_t length);
std::string getAddressString(struct CDPLayer::Address address);
bool operator==(const CDPLayer::Address& lhs, const CDPLayer::Address& rhs);

#endif // CDPLAYER_HPP