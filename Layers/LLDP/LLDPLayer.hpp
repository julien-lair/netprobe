#ifndef LLDPLAYER_HPP
#define LLDPLAYER_HPP

#include <arpa/inet.h>
#include <string>
#include <vector>
#include <iostream>
#include <unordered_map>
#include <stdexcept>
#include <iomanip>

// Class representing LLDP Layer
/**
 * @class LLDPLayer
 * 
 * @brief Represents an LLDP layer in a network packet.
 * 
 * The LLDPLayer class provides methods for accessing and parsing LLDP data from a network packet.
 * It extracts information such as the chassis ID, port ID, TTL, port description, system name,
 * system description, system capabilities, and management address from the LLDP packet.
 * 
 * The LLDPLayer class also provides an overloaded operator for outputting LLDP layer information.
 */
class LLDPLayer {
public:
    // Constructor and Destructor
    LLDPLayer(const uint8_t* data, size_t dataLen);
    ~LLDPLayer();

    enum ChassisSubtype {
        CHASSIS_ID_SUBTYPE_RESERVED = 0,
        CHASSIS_ID_SUBTYPE_CHASSIS_COMPONENT = 1,
        CHASSIS_ID_SUBTYPE_INTERFACE_ALIAS = 2,
        CHASSIS_ID_SUBTYPE_PORT_COMPONENT = 3,
        CHASSIS_ID_SUBTYPE_MAC_ADDRESS = 4,
        CHASSIS_ID_SUBTYPE_NETWORK_ADDRESS = 5,
        CHASSIS_ID_SUBTYPE_INTERFACE_NAME = 6,
        CHASSIS_ID_SUBTYPE_LOCALLY_ASSIGNED = 7
    };

    struct Chassis {
        ChassisSubtype subtype;
        std::string id;
    };

     // Enums for representing LLDP types and subtypes
    enum LLDPTlvType {
        LLDP_TLV_TYPE_END_OF_LLDPDU = 0,
        LLDP_TLV_TYPE_CHASSIS_ID = 1,
        LLDP_TLV_TYPE_PORT_ID = 2,
        LLDP_TLV_TYPE_TTL = 3,
        LLDP_TLV_TYPE_PORT_DESCRIPTION = 4,
        LLDP_TLV_TYPE_SYSTEM_NAME = 5,
        LLDP_TLV_TYPE_SYSTEM_DESCRIPTION = 6,
        LLDP_TLV_TYPE_SYSTEM_CAPABILITIES = 7,
        LLDP_TLV_TYPE_MANAGEMENT_ADDRESS = 8,
        LLDP_TLV_TYPE_ORGANIZATION_SPECIFIC = 127
    };

    enum PortSubtype {
        PORT_ID_SUBTYPE_INTERFACE_ALIAS = 1,
        PORT_ID_SUBTYPE_PORT_COMPONENT = 2,
        PORT_ID_SUBTYPE_MAC_ADDRESS = 3,
        PORT_ID_SUBTYPE_NETWORK_ADDRESS = 4,
        PORT_ID_SUBTYPE_INTERFACE_NAME = 5,
        PORT_ID_SUBTYPE_AGENT_CIRCUIT_ID = 6,
        PORT_ID_SUBTYPE_LOCALLY_ASSIGNED = 7
    };

    enum SystemCapabilities {
        CAP_OTHER = 1 << 0,
        CAP_REPEATER = 1 << 1,
        CAP_BRIDGE = 1 << 2,
        CAP_AP = 1 << 3,
        CAP_ROUTER = 1 << 4,
        CAP_TELEPHONE = 1 << 5,
        CAP_DOCSIS_CABLE_DEVICE = 1 << 6,
        CAP_STATION_ONLY = 1 << 7,
        CAP_CVLAN = 1 << 8,
        CAP_SVLAN = 1 << 9,
        CAP_TWO_PORT_MAC_RELAY = 1 << 10
    };

    enum ManagementAddressSubtype {
        MANAGEMENT_ADDRESS_SUBTYPE_IPV4 = 1,
        MANAGEMENT_ADDRESS_SUBTYPE_IPV6 = 2,
        MANAGEMENT_ADDRESS_SUBTYPE_MAC = 6
    };

    enum ManagementAddressInterfaceNumbering {
        MANAGEMENT_ADDRESS_INTERFACE_NUMBERING_UNKNOWN = 1,
        MANAGEMENT_ADDRESS_INTERFACE_NUMBERING_IF_INDEX = 2,
        MANAGEMENT_ADDRESS_INTERFACE_NUMBERING_SYSTEM_PORT_NUMBER = 3
    };

    // Structs for representing LLDP components
    struct Port {
        PortSubtype subtype;
        std::string id;
    };

    struct SystemCapability {
        SystemCapabilities type;
        bool enabled;
    };

    struct ManagementAddress {
        ManagementAddressSubtype subtype;
        std::string address;
        ManagementAddressInterfaceNumbering interfaceNumbering;
        uint32_t interfaceNumber;
        std::string oid;
    };


    // Public methods for accessing LLDP data
    struct LLDPLayer::Chassis getChassis() const;
    std::string getPortId() const;
    uint16_t getTTL() const;
    std::string getPortDescription() const;
    std::string getSystemName() const;
    std::string getSystemDescription() const;
    std::vector<struct LLDPLayer::SystemCapability> getSystemCapabilities() const;
    struct LLDPLayer::ManagementAddress getManagementAddress() const;

    // Overloaded operator for outputting LLDP layer information
    friend std::ostream& operator<<(std::ostream& os, const LLDPLayer& layer);

private:
    // Data members for LLDP processing
    const uint8_t* rawData;
    size_t rawDataLength;

    struct TLV {
        uint8_t type;
        uint16_t length;
        const uint8_t* value;
    };

    // Helper functions
    void parseTLVs();
    TLV getTLV(uint8_t type) const;
    std::string capabilitiesToString(const std::vector<SystemCapability>& capabilities) const;

    // Data structures for storing parsed TLVs
    std::vector<TLV> tlvs;
    const std::unordered_map<SystemCapabilities, std::string> capabilitiesMap = {
        {CAP_OTHER, "Other"},
        {CAP_REPEATER, "Repeater"},
        {CAP_BRIDGE, "Bridge"},
        {CAP_AP, "Access Point"},
        {CAP_ROUTER, "Router"},
        {CAP_TELEPHONE, "Telephone"},
        {CAP_DOCSIS_CABLE_DEVICE, "DOCSIS Cable Device"},
        {CAP_STATION_ONLY, "Station Only"},
        {CAP_CVLAN, "C-VLAN"},
        {CAP_SVLAN, "S-VLAN"},
        {CAP_TWO_PORT_MAC_RELAY, "Two-Port MAC Relay"}
    };
};

#endif // LLDPLAYER_HPP
