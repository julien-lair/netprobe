#ifndef STP_LAYER_HPP
#define STP_LAYER_HPP

#include "MacAddress.h"

#include <cstdint>
#include <cstddef> 
#include <stdexcept>
#include <iostream> 
#include <iomanip>
#include <algorithm>

// Helper function to reverse byte order for 16-bit values
uint16_t reverseBytes16(uint16_t value);
// Helper function to reverse byte order for 32-bit values
uint32_t reverseBytes32(uint32_t value) ;
uint64_t reverseBytes48(uint64_t value);

// Helper function to reverse byte order for 64-bit values
uint64_t reverseBytes64(uint64_t value);

// STP Layer class
/**
 * @class STPLayer
 * 
 * @brief Represents an STP layer in a network packet.
 * 
 * The STPLayer class provides methods for accessing and parsing STP data from a network packet.
 * It extracts information such as the Root Identifier, Bridge Identifier, and system ID from the STP packet.
 * 
 * The STPLayer class also provides an overloaded operator for outputting STP layer information.
 */
class STPLayer {
  public: 
    STPLayer(const uint8_t* data, size_t dataLen);
    ~STPLayer();

    struct RootIdentifier {
        uint16_t priority;
        uint8_t systemIDExtension;
        uint64_t systemID;
    } __attribute__((packed));

    struct RootIdentifier getRootIdentifier() const;

    struct BridgeIdentifier {
        uint16_t priority;
        uint8_t systemIDExtension;
        uint64_t systemID;
    } __attribute__((packed));

    struct BridgeIdentifier getBridgeIdentifier() const;

    pcpp::MacAddress getRootBridgeSystemID() const;
    pcpp::MacAddress getLocalBridgeSystemID() const;

    STPLayer(const STPLayer&) = delete;
    
  private:
    const uint8_t* rawData;
    size_t rawDataLength;

    struct CBDU {
        uint8_t bpduType;
        uint8_t flags;
        uint64_t RootIdentifier;
        uint32_t RootPathCost;
        uint64_t BridgeIdentifier;
        uint16_t PortIdentifier;
        uint16_t MessageAge;
        uint16_t MaxAge;
        uint16_t HelloTime;
        uint16_t ForwardDelay;
    } __attribute__((packed));

    struct CBDU cbdu;

    void parseSTPDU();
    struct CBDU getCBDU() const;

    friend std::ostream& operator<<(std::ostream& os, const STPLayer& layer);
};

#endif // STP_LAYER_HPP
