#include "STPLayer.hpp"

// Helper function to reverse byte order for 16-bit values
uint16_t reverseBytes16(uint16_t value) {
    return (value >> 8) | (value << 8);
}

// Helper function to reverse byte order for 32-bit values
uint32_t reverseBytes32(uint32_t value) {
    return ((value >> 24) & 0x000000FF) |
           ((value >> 8) & 0x0000FF00) |
           ((value << 8) & 0x00FF0000) |
           ((value << 24) & 0xFF000000);
}

uint64_t reverseBytes48(uint64_t value) {
    // Reverse only the lower 6 bytes (48 bits)
    return ((value >> 40) & 0x00000000000000FF) |
           ((value >> 24) & 0x000000000000FF00) |
           ((value >> 8)  & 0x0000000000FF0000) |
           ((value << 8)  & 0x00000000FF000000) |
           ((value << 24) & 0x000000FF00000000) |
           ((value << 40) & 0x00FF000000000000);
}

// Helper function to reverse byte order for 64-bit values
uint64_t reverseBytes64(uint64_t value) {
    return ((value >> 56) & 0x00000000000000FF) |
           ((value >> 40) & 0x000000000000FF00) |
           ((value >> 24) & 0x0000000000FF0000) |
           ((value >> 8) & 0x00000000FF000000) |
           ((value << 8) & 0x000000FF00000000) |
           ((value << 24) & 0x0000FF0000000000) |
           ((value << 40) & 0x00FF000000000000) |
           ((value << 56) & 0xFF00000000000000);
}

// Function to print the Bridge System ID with colons
void printBridgeSystemID(std::ostream& os, uint64_t systemID) {
    uint64_t reversedSystemID = reverseBytes64(systemID);
    uint8_t bytes[8];
    for (int i = 0; i < 8; ++i) {
        bytes[i] = (reversedSystemID >> (56 - 8 * i)) & 0xFF;
    }

    os << "Bridge System ID: 0x";
    for (int i = 0; i < 8; ++i) {
        if (i > 0) {
            os << ":";
        }
        os << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
    }
    os << std::endl;
}

// Constructor
STPLayer::STPLayer(const uint8_t* data, size_t dataLen) : rawData(data), rawDataLength(dataLen) {
    // Check if the data length is valid for STP
    if (dataLen < 35) {
        throw std::invalid_argument("Invalid STPDU size");
    }

    // Parse STPDU
    parseSTPDU();
}

// Destructor
STPLayer::~STPLayer() {
    // Destructor implementation (if needed)
}

// Parsing the entire STPDU
/**
 * @brief Parses the STPDU (Spanning Tree Protocol Data Unit) from the raw data.
 *
 * This function extracts the root identifier and bridge identifier from the STPDU.
 * The root identifier contains the priority, system ID extension, and system ID of
 * the root bridge. The bridge identifier contains the priority, system ID extension,
 * and system ID of the local bridge.
 */

void STPLayer::parseSTPDU() {
    std::copy(rawData, rawData + rawDataLength, reinterpret_cast<uint8_t*>(&cbdu));
}

// Get the CBDU
/**
 * @brief Gets the CBPDU (Configuration Bridge Protocol Data Unit) from the STPDU.
 *
 * @return The CBPDU.
 */

struct STPLayer::CBDU STPLayer::getCBDU() const {
    return cbdu;
}

// Get the root identifier
/**
 * @brief Gets the root identifier from the STPDU.
 *
 * @return The root identifier.
 */

struct STPLayer::RootIdentifier STPLayer::getRootIdentifier() const {
    struct RootIdentifier rootIdentifier;
    std::copy(const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(&cbdu.RootIdentifier)), const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(&cbdu.RootIdentifier)) + 8, reinterpret_cast<uint8_t*>(&rootIdentifier));
    rootIdentifier.systemIDExtension = rootIdentifier.priority >> 8;
    rootIdentifier.priority = rootIdentifier.priority & 0x00FF;
    rootIdentifier.systemID = (rootIdentifier.systemID << 8 | rootIdentifier.systemIDExtension);
    return rootIdentifier;
}

// Get the bridge identifier
/**
 * @brief Gets the bridge identifier from the STPDU.
 *
 * @return The bridge identifier.
 */

struct STPLayer::BridgeIdentifier STPLayer::getBridgeIdentifier() const {
    struct BridgeIdentifier bridgeIdentifier;
    std::copy(const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(&cbdu.BridgeIdentifier)), const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(&cbdu.BridgeIdentifier)) + 8, reinterpret_cast<uint8_t*>(&bridgeIdentifier));
    bridgeIdentifier.systemIDExtension = bridgeIdentifier.priority >> 8;
    bridgeIdentifier.priority = bridgeIdentifier.priority & 0x00FF;
    bridgeIdentifier.systemID = (bridgeIdentifier.systemID << 8 | bridgeIdentifier.systemIDExtension) & 0x00FFFFFFFFFFFF;
    return bridgeIdentifier;
}

// Get the root bridge system ID
/**
 * @brief Gets the root bridge system ID from the STPDU.
 *
 * @return The root bridge system ID.
 */

pcpp::MacAddress STPLayer::getRootBridgeSystemID() const {
    struct RootIdentifier rootIdentifier = getRootIdentifier();
    uint64_t reversedSystemID = reverseBytes64(rootIdentifier.systemID);
    return pcpp::MacAddress(reinterpret_cast<uint8_t*>(&reversedSystemID));
}

// Get the local bridge system ID
/**
 * @brief Gets the local bridge system ID from the STPDU.
 *
 * @return The local bridge system ID.
 */

pcpp::MacAddress STPLayer::getLocalBridgeSystemID() const {
    struct BridgeIdentifier bridgeIdentifier = getBridgeIdentifier();
    uint64_t reversedSystemID = reverseBytes64(bridgeIdentifier.systemID);
    return pcpp::MacAddress(reinterpret_cast<uint8_t*>(&reversedSystemID));
}

// Overloaded stream insertion operator for STPLayer
/**
 * @brief Overloads the stream insertion operator for STPLayer.
 *
 * @param os The output stream.
 * @param layer The STPLayer object.
 * @return The output stream.
 */

std::ostream& operator<<(std::ostream& os, const STPLayer& layer) {
    struct STPLayer::RootIdentifier rootIdentifier = layer.getRootIdentifier();
    struct STPLayer::BridgeIdentifier bridgeIdentifier = layer.getBridgeIdentifier();

    os << "BPDU Type: " << std::hex << int(layer.cbdu.bpduType) << std::endl;
    os << "Flags: " << std::hex << int(layer.cbdu.flags) << std::endl;
    uint16_t reversedRootIdentifier = reverseBytes16(rootIdentifier.priority);
    os << "Root Bridge Priority: " << std::dec << reversedRootIdentifier << std::endl;
    os << "Root Bridge System ID Extension: " << std::dec << int(rootIdentifier.systemIDExtension) << std::endl;
    uint64_t reversedRootID = reverseBytes64(rootIdentifier.systemID);
    os << "Root Bridge System ID: " << std::hex << std::setfill('0');
    os << std::setw(2) << (reversedRootID >> 40 & 0xFF) << ":";
    os << std::setw(2) << (reversedRootID >> 32 & 0xFF) << ":";
    os << std::setw(2) << (reversedRootID >> 24 & 0xFF) << ":";
    os << std::setw(2) << (reversedRootID >> 16 & 0xFF) << ":";
    os << std::setw(2) << (reversedRootID >> 8 & 0xFF) << ":";
    os << std::setw(2) << (reversedRootID & 0xFF) << std::endl;
    os << "Root Path Cost: 0x" << std::hex << reverseBytes32(layer.cbdu.RootPathCost) << std::endl;
    uint16_t reversedBridgeIdentifier = reverseBytes16(bridgeIdentifier.priority);
    os << "Bridge Priority: " << std::dec << reversedBridgeIdentifier << std::endl;
    os << "Bridge System ID Extension: " << std::dec << int(bridgeIdentifier.systemIDExtension) << std::endl;
    uint64_t reversedSystemID = reverseBytes64(bridgeIdentifier.systemID);
    os << "Bridge System ID: " << std::hex << std::setfill('0');
    os << std::setw(2) << (reversedSystemID >> 40 & 0xFF) << ":";
    os << std::setw(2) << (reversedSystemID >> 32 & 0xFF) << ":";
    os << std::setw(2) << (reversedSystemID >> 24 & 0xFF) << ":";
    os << std::setw(2) << (reversedSystemID >> 16 & 0xFF) << ":";
    os << std::setw(2) << (reversedSystemID >> 8 & 0xFF) << ":";
    os << std::setw(2) << (reversedSystemID & 0xFF) << std::endl;
    os << "Port Identifier: 0x" << std::hex << std::setw(4) << std::setfill('0') << reverseBytes16(layer.cbdu.PortIdentifier) << std::endl;
    os << "Message Age: " << std::dec << layer.cbdu.MessageAge << std::endl;
    os << "Max Age: " << std::dec << layer.cbdu.MaxAge << std::endl;
    os << "Hello Time: " << std::dec << layer.cbdu.HelloTime << std::endl;
    os << "Forward Delay: " << std::dec << layer.cbdu.ForwardDelay << std::endl;
    return os;
}

