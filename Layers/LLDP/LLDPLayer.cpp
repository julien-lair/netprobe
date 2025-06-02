#include "LLDPLayer.hpp"
#include <stdexcept>
#include <iostream>
#include <iomanip>

// Constructor
LLDPLayer::LLDPLayer(const uint8_t* data, size_t dataLen) : rawData(data), rawDataLength(dataLen) {
    // Check if the data length is valid for LLDP
    if (dataLen < 2) {
        throw std::invalid_argument("Invalid LLDPDU size");
    }

    // Parse TLVs
    parseTLVs();
}

// Destructor
LLDPLayer::~LLDPLayer() {
    // Destructor implementation (if needed)
}

// Parsing the entire LLDP TLV block
void LLDPLayer::parseTLVs() {
    size_t offset = 0;

    while (offset < rawDataLength) {
        // Ensure there's at least two bytes remaining for TLV header
        if (rawDataLength - offset < 2) {
            throw std::runtime_error("Incomplete TLV header");
        }

        // Extract TLV type and length (first 2 bytes)
        uint16_t tlvTypeLength = ntohs(*reinterpret_cast<const uint16_t*>(rawData + offset));
        uint8_t tlvType = (tlvTypeLength >> 9) & 0x7F;  // First 7 bits for type
        uint16_t tlvLength = tlvTypeLength & 0x1FF;      // Last 9 bits for length
        offset += 2;

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

        // Stop parsing if this is the End of LLDPDU TLV
        if (tlvType == LLDP_TLV_TYPE_END_OF_LLDPDU) {
            break;
        }
    }
}

LLDPLayer::TLV LLDPLayer::getTLV(uint8_t type) const {
    for (const TLV& tlv : tlvs) {
        if (tlv.type == type) {
            return tlv;
        }
    }

    // Return an empty TLV if not found
    return {0, 0, nullptr};
}

// Getters for specific TLVs
struct LLDPLayer::Chassis LLDPLayer::getChassis() const {
    TLV tlv = getTLV(LLDP_TLV_TYPE_CHASSIS_ID);
    if (tlv.length == 0) {
        return {CHASSIS_ID_SUBTYPE_LOCALLY_ASSIGNED, ""}; // Default value
    }

    // Extract the subtype and value
    ChassisSubtype subtype = static_cast<ChassisSubtype>(tlv.value[0]); // Cast to ChassisIdSubtype
   // If MAC address, convert to string
    std::string value;
    if (subtype == CHASSIS_ID_SUBTYPE_MAC_ADDRESS) {
        std::stringstream ss;
        for (size_t i = 1; i < tlv.length; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)tlv.value[i];
            if (i < tlv.length - 1) {
                ss << ":";
            }
        }
        value = ss.str();
    } else {
        value = std::string(reinterpret_cast<const char*>(tlv.value + 1), tlv.length - 1);
    }

    return {subtype, value}; // Return the constructed ChassisId
}

std::string LLDPLayer::getPortId() const {
    TLV tlv = getTLV(LLDP_TLV_TYPE_PORT_ID);
    if (tlv.length == 0) {
        return "";
    }

    // Extract the subtype and value
    PortSubtype subtype = static_cast<PortSubtype>(tlv.value[0]);
    std::string value;

    // If MAC address, convert to string
    if (subtype == PORT_ID_SUBTYPE_MAC_ADDRESS) {
        std::stringstream ss;
        for (size_t i = 1; i < tlv.length; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)tlv.value[i];
            if (i < tlv.length - 1) {
                ss << ":";
            }
        }
        value = ss.str();
    } else {
        value = std::string(reinterpret_cast<const char*>(tlv.value + 1), tlv.length - 1);
    }

    return value;
}

std::string LLDPLayer::getSystemName() const {
    TLV tlv = getTLV(LLDP_TLV_TYPE_SYSTEM_NAME);
    if (tlv.length == 0) {
        return "";
    }

    return std::string(reinterpret_cast<const char*>(tlv.value), tlv.length);
}

uint16_t LLDPLayer::getTTL() const {
    TLV tlv = getTLV(LLDP_TLV_TYPE_TTL);
    if (tlv.length == 0) {
        return 0;
    }

    return ntohs(*reinterpret_cast<const uint16_t*>(tlv.value));
}

std::string LLDPLayer::getSystemDescription() const {
    TLV tlv = getTLV(LLDP_TLV_TYPE_SYSTEM_DESCRIPTION);
    if (tlv.length == 0) {
        return "";
    }

    return std::string(reinterpret_cast<const char*>(tlv.value), tlv.length);
}

std::string LLDPLayer::getPortDescription() const {
    TLV tlv = getTLV(LLDP_TLV_TYPE_PORT_DESCRIPTION);
    if (tlv.length == 0) {
        return "";
    }

    return std::string(reinterpret_cast<const char*>(tlv.value), tlv.length);
}

struct LLDPLayer::ManagementAddress LLDPLayer::getManagementAddress() const {
    TLV tlv = getTLV(LLDP_TLV_TYPE_MANAGEMENT_ADDRESS);
    if (tlv.length == 0) {
        return {MANAGEMENT_ADDRESS_SUBTYPE_IPV4, "", MANAGEMENT_ADDRESS_INTERFACE_NUMBERING_UNKNOWN, 0};
    }

    uint8_t address_len = tlv.value[0];

    // Extract the subtype and value
    ManagementAddressSubtype subtype = static_cast<ManagementAddressSubtype>(tlv.value[1]);
    std::string value;
    if (subtype == MANAGEMENT_ADDRESS_SUBTYPE_IPV4) {
        value = std::to_string(tlv.value[2]) + "." + std::to_string(tlv.value[3]) + "." + std::to_string(tlv.value[4]) + "." + std::to_string(tlv.value[5]);
    } else if (subtype == MANAGEMENT_ADDRESS_SUBTYPE_IPV6) {
        // IPv6 address parsing (if needed)
    } else if (subtype == MANAGEMENT_ADDRESS_SUBTYPE_MAC) {
        std::stringstream ss;
        for (size_t i = 2; i < address_len + 2; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)tlv.value[i];
            if (i < address_len + 1) {
                ss << ":";
            }
        }
        value = ss.str();
    }

    // Extract the interface numbering
    ManagementAddressInterfaceNumbering interfaceNumbering = static_cast<ManagementAddressInterfaceNumbering>(tlv.value[2 + address_len]);
    uint32_t interfaceNumber = 0;

    // If the interface numbering is known, extract the interface number
    if (interfaceNumbering != MANAGEMENT_ADDRESS_INTERFACE_NUMBERING_UNKNOWN) {
        interfaceNumber = ntohl(*reinterpret_cast<const uint32_t*>(tlv.value + 3 + address_len));
    }

    uint8_t oid_len = tlv.value[3 + address_len];
    std::string oid = std::string(reinterpret_cast<const char*>(tlv.value + 4 + address_len), oid_len);

    return {subtype, value, interfaceNumbering, interfaceNumber, oid};
}

std::vector<struct LLDPLayer::SystemCapability> LLDPLayer::getSystemCapabilities() const {
    // Get the TLV for system capabilities
    TLV tlv = getTLV(LLDP_TLV_TYPE_SYSTEM_CAPABILITIES);
    std::vector<struct SystemCapability> capabilities;

    // Ensure the TLV has the expected length (4 bytes: 2 for supported, 2 for enabled)
    if (tlv.length < 4) {
        return capabilities;  // Return an empty vector if the TLV is invalid
    }

    // Extract the system capabilities and enabled capabilities (each 2 bytes)
    uint16_t supportedCapabilities = ntohs(*reinterpret_cast<const uint16_t*>(tlv.value));
    uint16_t enabledCapabilities = ntohs(*reinterpret_cast<const uint16_t*>(tlv.value + 2));

    // Add each capability to the vector based on the bitmask
    if (supportedCapabilities & CAP_OTHER) {
        capabilities.push_back({CAP_OTHER, static_cast<bool>(enabledCapabilities & CAP_OTHER)});
    }
    if (supportedCapabilities & CAP_REPEATER) {
        capabilities.push_back({CAP_REPEATER, static_cast<bool>(enabledCapabilities & CAP_REPEATER)});
    }
    if (supportedCapabilities & CAP_BRIDGE) {
        capabilities.push_back({CAP_BRIDGE, static_cast<bool>(enabledCapabilities & CAP_BRIDGE)});
    }
    if (supportedCapabilities & CAP_AP) {
        capabilities.push_back({CAP_AP, static_cast<bool>(enabledCapabilities & CAP_AP)});
    }
    if (supportedCapabilities & CAP_ROUTER) {
        capabilities.push_back({CAP_ROUTER, static_cast<bool>(enabledCapabilities & CAP_ROUTER)});
    }
    if (supportedCapabilities & CAP_TELEPHONE) {
        capabilities.push_back({CAP_TELEPHONE, static_cast<bool>(enabledCapabilities & CAP_TELEPHONE)});
    }
    if (supportedCapabilities & CAP_DOCSIS_CABLE_DEVICE) {
        capabilities.push_back({CAP_DOCSIS_CABLE_DEVICE, static_cast<bool>(enabledCapabilities & CAP_DOCSIS_CABLE_DEVICE)});
    }
    if (supportedCapabilities & CAP_STATION_ONLY) {
        capabilities.push_back({CAP_STATION_ONLY, static_cast<bool>(enabledCapabilities & CAP_STATION_ONLY)});
    }

    return capabilities;
}

// Convert LLDP capabilities to a string
std::string LLDPLayer::capabilitiesToString(const std::vector<struct SystemCapability>& capabilities) const {
    std::stringstream ss;
    for (const auto& capability : capabilities) {
        ss << capabilitiesMap.at(capability.type) << " (" << (capability.enabled ? "Enabled" : "Disabled") << "), ";
    }
    std::string capabilitiesStr = ss.str();
    if (!capabilitiesStr.empty()) {
        capabilitiesStr.pop_back(); // Remove the trailing comma
        capabilitiesStr.pop_back(); // Remove the trailing space
    }
    return capabilitiesStr;
}

std::ostream& operator<<(std::ostream& os, const LLDPLayer& layer) {
    os << "Chassis ID: " << layer.getChassis().id << "\n";
    os << "Port ID: " << layer.getPortId() << "\n";
    os << "TTL: " << layer.getTTL() << "\n";
    os << "Port Description: " << layer.getPortDescription() << "\n";
    os << "System Name: " << layer.getSystemName() << "\n";
    os << "System Description: " << layer.getSystemDescription() << "\n";
    os << "System Capabilities: " << layer.capabilitiesToString(layer.getSystemCapabilities()) << "\n";
    os << "Management Address: " << layer.getManagementAddress().address << "\n";
    return os;
}


