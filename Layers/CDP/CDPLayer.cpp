#include "CDPLayer.hpp"

CDPLayer::CDPLayer(const uint8_t* data, size_t dataLen) : rawData(data), rawDataLength(dataLen) {
    // Check if the data length is valid for CDP
    if (dataLen < 4) {
        throw std::invalid_argument("Invalid CDPDU size");
    }

    // Parse TLVs
    parseTLVs();
}

CDPLayer::~CDPLayer() {
    // Destructor implementation (if needed)
}

void CDPLayer::parseTLVs() {
    size_t offset = 0;

    while (offset < rawDataLength) {
        // Ensure there's at least three bytes remaining for TLV header
        if (rawDataLength - offset < 3) {
            throw std::runtime_error("Incomplete TLV header");
        }

        // Extract TLV type and length (first 2 bytes)
        uint16_t tlvType = (rawData[offset] << 8) | rawData[offset + 1];
        uint16_t tlvLength = (rawData[offset + 2] << 8) | rawData[offset + 3];

        // Ensure there's enough data left for the TLV value
        if (offset + tlvLength > rawDataLength) {
            throw std::runtime_error("TLV length exceeds available data");
        }

        // Extract TLV value
        const uint8_t* tlvValue = rawData + offset;

        // Create a TLV struct and add it to the list
        TLV tlv = {tlvType, tlvLength, tlvValue};
        tlvs.push_back(tlv);

        // Move the offset to the next TLV
        offset += tlvLength;
    }
}

CDPLayer::TLV CDPLayer::getTLV(uint8_t type) const {
    for (const TLV& tlv : tlvs) {
        if (tlv.type == type) {
            return tlv;
        }
    }

    return {0, 0, nullptr};
}

struct CDPLayer::DeviceId CDPLayer::getDeviceId() const {
    TLV tlv = getTLV(CDP_TLV_TYPE_DEVICE_ID);
    DeviceId deviceId;

    // Ensure the TLV has a valid length
    if (tlv.length < 2) {
        return deviceId;
    }

    // Extract the subtype and value
    deviceId.subtype = static_cast<DeviceIdSubtype>(tlv.value[0]);
    deviceId.id = std::string(reinterpret_cast<const char*>(tlv.value + 1), tlv.length - 1);

    return deviceId;
}

struct CDPLayer::Addresses CDPLayer::getAddresses() const {
    TLV tlv = getTLV(CDP_TLV_TYPE_ADDRESS);
    Addresses addresses;

    // Ensure the TLV has a valid length
    if (tlv.length < 1) {
        return addresses;
    }

    // Extract the number of addresses offset 4 bytes and convert to integer
    addresses.numberOfAddresses = tlv.value[4] << 24 | tlv.value[5] << 16 | tlv.value[6] << 8 | tlv.value[7];
   

    // Ensure the TLV has a valid length
    if (tlv.length < 1 + addresses.numberOfAddresses * 5) {
        return addresses;
    }

    // Extract the addresses
    for (size_t i = 0; i < addresses.numberOfAddresses; i++) {
        Address address;
        address.protocolType = tlv.value[8 + i * 5];
        address.protocolLength = tlv.value[9 + i * 5];
        address.protocol = tlv.value[10 + i * 5];
        address.addressLength = tlv.value[11 + i * 5] << 8 | tlv.value[12 + i * 5];
        address.address = tlv.value + 13 + i * 5;
        addresses.addresses.push_back(address);
    }

    return addresses;
}

std::string CDPLayer::getPortId() const {
    TLV tlv = getTLV(CDP_TLV_TYPE_PORT_ID);

    // Ensure the TLV has a valid length
    if (tlv.length < 1) {
        return "";
    }

    return std::string(reinterpret_cast<const char*>(tlv.value), tlv.length);
}

uint32_t CDPLayer::getCapabilities() const {
    TLV tlv = getTLV(CDP_TLV_TYPE_CAPABILITIES);

    // Ensure the TLV has a valid length
    if (tlv.length < 4) {
        return 0;
    }

    return (tlv.value[4] << 24) | (tlv.value[5] << 16) | (tlv.value[6] << 8) | tlv.value[7];
}

std::string CDPLayer::capabilitiesToString(uint32_t capabilities) const {
    std::ostringstream oss;
    if (capabilities & CAPABILITY_ROUTER) oss << "Router ";
    if (capabilities & CAPABILITY_TRANSPARENT_BRIDGE) oss << "Transparent Bridge ";
    if (capabilities & CAPABILITY_SOURCE_ROUTE_BRIDGE) oss << "Source Route Bridge ";
    if (capabilities & CAPABILITY_SWITCH) oss << "Switch ";
    if (capabilities & CAPABILITY_HOST) oss << "Host ";
    if (capabilities & CAPABILITY_IGMP) oss << "IGMP ";
    if (capabilities & CAPABILITY_REPEATER) oss << "Repeater ";
    if (capabilities & CAPABILITY_VOIP_PHONE) oss << "VoIP Phone ";
    if (capabilities & CAPABILITY_REMOTELY_MANAGED) oss << "Remotely Managed ";
    if (capabilities & CAPABILITY_CVTA) oss << "CVTA ";
    if (capabilities & CAPABILITY_TWO_PORT_MAC_RELAY) oss << "Two Port MAC Relay ";
    return oss.str();
}

std::string CDPLayer::getSoftwareVersion() const {
    TLV tlv = getTLV(CDP_TLV_TYPE_SOFTWARE_VERSION);

    // Ensure the TLV has a valid length
    if (tlv.length < 1) {
        return "";
    }

    // Convert the TLV value to a std::string
    std::string softwareVersion(reinterpret_cast<const char*>(tlv.value), tlv.length);

    // Remove every 0x0A byte (newline character) from the string
    softwareVersion.erase(
        std::remove(softwareVersion.begin(), softwareVersion.end(), '\n'),
        softwareVersion.end()
    );

    return softwareVersion;
}

std::string CDPLayer::getPlatform() const {
    TLV tlv = getTLV(CDP_TLV_TYPE_PLATFORM);

    // Ensure the TLV has a valid length
    if (tlv.length < 1) {
        return "";
    }

    // Convert the TLV value to a std::string
    std::string platform(reinterpret_cast<const char*>(tlv.value), tlv.length);

    // Remove every 0x0A byte (newline character) from the string
    platform.erase(
        std::remove(platform.begin(), platform.end(), '\n'),
        platform.end()
    );

    return platform;
}

std::string CDPLayer::getVTPManagementDomain() const {
    TLV tlv = getTLV(CDP_TLV_TYPE_VTP_MANAGEMENT_DOMAIN);

    // Ensure the TLV has a valid length
    if (tlv.length < 1) {
        return "";
    }

    return std::string(reinterpret_cast<const char*>(tlv.value), tlv.length);
}

uint8_t CDPLayer::getDuplex() const {
    TLV tlv = getTLV(CDP_TLV_TYPE_DUPLEX);

    // Ensure the TLV has a valid length
    if (tlv.length < 1) {
        return 0;
    }

    return tlv.value[4];
}

uint16_t CDPLayer::getNativeVlan() const {
    TLV tlv = getTLV(CDP_TLV_TYPE_NATIVE_VLAN);

    // Ensure the TLV has a valid length
    if (tlv.length < 2) {
        return 0;
    }

    return (tlv.value[4] << 8) | tlv.value[5];
}

uint8_t CDPLayer::getTrustBitmap() const {
    TLV tlv = getTLV(CDP_TLV_TYPE_TRUST_BITMAP);

    // Ensure the TLV has a valid length
    if (tlv.length < 1) {
        return 0;
    }

    return tlv.value[4];
}

uint8_t CDPLayer::getUntrustedPortCos() const {
    TLV tlv = getTLV(CDP_TLV_TYPE_UNTRUSTED_PORT_COS);

    // Ensure the TLV has a valid length
    if (tlv.length < 1) {
        return 0;
    }

    return tlv.value[4];
}

struct CDPLayer::Addresses CDPLayer::getMgmtAddresses() const {
    TLV tlv = getTLV(CDP_TLV_TYPE_MGMT_ADDRESS);
    Addresses addresses;

    // Ensure the TLV has a valid length
    if (tlv.length < 1) {
        return addresses;
    }

    // Extract the number of addresses offset 4 bytes and convert to integer
    addresses.numberOfAddresses = tlv.value[4] << 24 | tlv.value[5] << 16 | tlv.value[6] << 8 | tlv.value[7];

    // Ensure the TLV has a valid length
    if (tlv.length < 1 + addresses.numberOfAddresses * 5) {
        return addresses;
    }

    // Extract the addresses
    for (size_t i = 0; i < addresses.numberOfAddresses; i++) {
        Address address;
        address.protocolType = tlv.value[8 + i * 5];
        address.protocolLength = tlv.value[9 + i * 5];
        address.protocol = tlv.value[10 + i * 5];
        address.addressLength = tlv.value[11 + i * 5] << 8 | tlv.value[12 + i * 5];
        address.address = tlv.value + 13 + i * 5;
        addresses.addresses.push_back(address);
    }

    return addresses;
}

std::ostream& operator<<(std::ostream& os, const CDPLayer& layer) {
    os << "CDP Layer" << std::endl;
    os << "  Device ID: " << layer.getDeviceId().id << std::endl;
    os << "  Addresses:" << std::endl;
    for (const auto& address : layer.getAddresses().addresses) {
        os << "    Protocol Type: " << address.protocolType << std::endl;
        os << "    Protocol Length: " << address.protocolLength << std::endl;
        os << "    Protocol: " << address.protocol << std::endl;
        os << "    Address Length: " << address.addressLength << std::endl;
        os << "    Address: " << toHexString(address.address, address.addressLength) << std::endl;
    }
    os << "  Port ID: " << layer.getPortId() << std::endl;
    os << "  Capabilities: " << layer.capabilitiesToString(layer.getCapabilities()) << std::endl;
    os << "  Software Version: " << layer.getSoftwareVersion() << std::endl;
    os << "  Platform: " << layer.getPlatform() << std::endl;
    os << "  VTP Management Domain: " << layer.getVTPManagementDomain() << std::endl;
    os << "  Native VLAN: " << layer.getNativeVlan() << std::endl;
    os << "  Duplex: " << (layer.getDuplex() == 0 ? "Half" : "Full") << std::endl;
    os << "  Trust Bitmap: " << layer.getTrustBitmap() << std::endl;
    os << "  Untrusted Port CoS: " << layer.getUntrustedPortCos() << std::endl;
    os << "  Management Addresses:" << std::endl;
    for (const auto& address : layer.getMgmtAddresses().addresses) {
        os << "    Protocol Type: " << address.protocolType << std::endl;
        os << "    Protocol Length: " << address.protocolLength << std::endl;
        os << "    Protocol: " << address.protocol << std::endl;
        os << "    Address Length: " << address.addressLength << std::endl;
        os << "    Address: " << toHexString(address.address, address.addressLength) << std::endl;
    }
    return os;
}

std::string toHexString(const uint8_t* data, size_t length) {
    std::ostringstream oss;
    for (size_t i = 0; i < length; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return oss.str();
}

std::string getAddressString(struct CDPLayer::Address address) {
    if(address.protocol == 0xcc) {
        // Return the ipv4 address
        return std::to_string(address.address[0]) + "." + std::to_string(address.address[1]) + "." + std::to_string(address.address[2]) + "." + std::to_string(address.address[3]);
    } else if(address.protocol == 0x86dd) {
        // Return the ipv6 address
        std::ostringstream oss;
        for (size_t i = 0; i < address.addressLength; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)address.address[i];
        }
        return oss.str();
    } else {
        // Return the address as a hex string
        return toHexString(address.address, address.addressLength);
    }
}

bool operator==(const CDPLayer::Address& lhs, const CDPLayer::Address& rhs) {
    return lhs.protocolType == rhs.protocolType &&
           lhs.protocolLength == rhs.protocolLength &&
           lhs.protocol == rhs.protocol &&
           lhs.addressLength == rhs.addressLength &&
           std::equal(lhs.address, lhs.address + lhs.addressLength, rhs.address);
}
