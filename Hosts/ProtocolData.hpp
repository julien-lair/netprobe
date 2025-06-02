#ifndef PROTOCOL_DATA_HPP
#define PROTOCOL_DATA_HPP

#include "MacAddress.h"
#include "IPv4Layer.h"
#include "../Layers/STP/STPLayer.hpp"
#include "../Layers/SSDP/SSDPLayer.hpp"
#include "../Layers/CDP/CDPLayer.hpp"
#include <string>
#include <ctime>
#include <unordered_set>
#include <json/json.h>

enum class ProtocolType {
    DHCP,
    MDNS,
    ARP,
    SSDP,
    LLDP,
    CDP,
    STP,
    WOL,
    ICMP,
    SNMP,
};

// Hash function for std::pair
struct PairHash {
    template <typename T1, typename T2>
    std::size_t operator()(const std::pair<T1, T2>& pair) const {
        return std::hash<T1>()(pair.first) ^ std::hash<T2>()(pair.second);
    }
};

// Base class for protocol data
/**
 * @class ProtocolData
 * @brief Base class for protocol-specific data.
 * 
 * The ProtocolData class is a base class for protocol-specific data structures.
 * It provides a common interface for accessing protocol data and a virtual
 * method to retrieve the protocol type.
 * 
 * Derived classes must implement the getProtocolType method to return the
 * specific protocol type.
 */
struct ProtocolData {
    ProtocolType protocol;
    timespec timestamp;
     ProtocolData(ProtocolType proto, timespec ts = {}) 
        : protocol(proto), timestamp(ts) {}
    virtual ~ProtocolData() = default;
    virtual ProtocolType getProtocolType() const {
        return protocol;
    }
    virtual Json::Value toJson() const {
        Json::Value jsonData;
        //add protcol in str 
        std::string protocolStr;
        switch (protocol) {
            case ProtocolType::DHCP:
                protocolStr = "DHCP";
                break;
            case ProtocolType::MDNS:
                protocolStr = "mDNS";
                break;
            case ProtocolType::ARP:
                protocolStr = "ARP";
                break;
            case ProtocolType::SSDP:
                protocolStr = "SSDP";
                break;
            case ProtocolType::LLDP:
                protocolStr = "LLDP";
                break;
            case ProtocolType::CDP:
                protocolStr = "CDP";
                break;
            case ProtocolType::STP:
                protocolStr = "STP";
                break;
            case ProtocolType::WOL:
                protocolStr = "WOL";
                break;
            case ProtocolType::ICMP:
                protocolStr = "ICMP";
                break;
            case ProtocolType::SNMP:
                protocolStr = "SNMP";
                break;
        }
        jsonData["PROTOCOL"] = protocolStr;
        jsonData["TIMESTAMP"] = std::to_string(timestamp.tv_sec) + "." + std::to_string(timestamp.tv_nsec); 
        return jsonData;
    }
};

// Data structure for DHCP protocol
/**
 * @struct DHCPData
 * @brief Data structure for DHCP protocol.
 * 
 * The DHCPData struct is a data structure for storing DHCP protocol data.
 * It contains fields for the client MAC address, client IP address, hostname,
 * DHCP server IP address, gateway IP address, and DNS server IP address.
 */
struct DHCPData : public ProtocolData {
    pcpp::MacAddress clientMac;
    pcpp::IPAddress ipAddress;
    std::string hostname;
    pcpp::IPAddress dhcpServerIp;
    pcpp::IPAddress gatewayIp;
    pcpp::IPAddress dnsServerIp;
    std::string fingerPrint;
    std::string messageType;

     // Constructor
    DHCPData(timespec ts, pcpp::MacAddress mac, pcpp::IPAddress ip, const std::string& host,
             pcpp::IPAddress dhcpServer, pcpp::IPAddress gateway, pcpp::IPAddress dns, std::string& OS_Supposition, std::string& DHCP_type)
        : ProtocolData(ProtocolType::DHCP, ts), clientMac(mac), ipAddress(ip),
          hostname(host), dhcpServerIp(dhcpServer), gatewayIp(gateway), dnsServerIp(dns), fingerPrint(OS_Supposition), messageType(DHCP_type) {}

    Json::Value toJson() const override {
        Json::Value jsonData = ProtocolData::toJson();  // ajoute les champs de base (timestamp, etc.)

        jsonData["MAC"] = clientMac.toString();
        jsonData["IP"] = ipAddress.toString();
        jsonData["HOSTNAME"] = hostname;
        jsonData["DHCP_SERVER"] = dhcpServerIp.toString();
        jsonData["GATEWAY"] = gatewayIp.toString();
        jsonData["DNS"] = dnsServerIp.toString();
        jsonData["FINGERPRINT"] = fingerPrint;
        jsonData["MESSAGE_TYPE"] = messageType;

        return jsonData;
    }
};

// Data structure for mDNS protocol
/**
 * @struct mDNSData
 * @brief Data structure for mDNS protocol.
 * 
 * The mDNSData struct is a data structure for storing mDNS protocol data.
 * It contains fields for the queried domain, client MAC address, hostname,
 * and IP address.
 */
struct mDNSData : public ProtocolData {
    std::string queriedDomain;
    pcpp::MacAddress clientMac;
    std::string hostname;
    pcpp::IPAddress ipAddress;
    std::string typeDNS;
    // Constructor
    mDNSData(timespec ts, const std::string& domain, pcpp::MacAddress mac, const std::string& host, pcpp::IPAddress ip, const std::string& type)
        : ProtocolData(ProtocolType::MDNS, ts), queriedDomain(domain), clientMac(mac), hostname(host), ipAddress(ip), typeDNS(type) { }

    Json::Value toJson() const override {
        Json::Value jsonData = ProtocolData::toJson();  // ajoute les champs de base (timestamp, etc.)

        jsonData["DOMAIN"] = queriedDomain;
        jsonData["MAC"] = clientMac.toString();
        jsonData["HOSTNAME"] = hostname;
        jsonData["IP"] = ipAddress.toString();
        jsonData["TYPE"] = typeDNS;

        return jsonData;
    }
};

// Data structure for ARP protocol
/**
 * @struct ARPData
 * @brief Data structure for ARP protocol.
 * 
 * The ARPData struct is a data structure for storing ARP protocol data.
 * It contains fields for the sender MAC address, sender IP address, and target IP address.
 */
struct ARPData : public ProtocolData {
    pcpp::MacAddress senderMac;
    pcpp::IPAddress senderIp;
    pcpp::IPAddress targetIp; 

    // Constructor
    ARPData(timespec ts, pcpp::MacAddress mac, pcpp::IPAddress sender, pcpp::IPAddress target)
        : ProtocolData(ProtocolType::ARP, ts), senderMac(mac), senderIp(sender), targetIp(target) {}

    Json::Value toJson() const override {
        Json::Value jsonData = ProtocolData::toJson();  // ajoute les champs de base (timestamp, etc.)

        jsonData["SENDER_MAC"] = senderMac.toString();
        jsonData["SENDER_IP"] = senderIp.toString();
        jsonData["TARGET_IP"] = targetIp.toString();

        return jsonData;
    }
};

// Data structure for LLDP protocol
/**
 * @struct LLDPData
 * @brief Data structure for LLDP protocol.
 * 
 * The LLDPData struct is a data structure for storing LLDP protocol data.
 * It contains fields for the sender MAC address, port ID, port description,
 * system name, and system description.
 */

struct LLDPData : public ProtocolData {
    pcpp::MacAddress senderMAC;
    std::string portID;
    std::string portDescription;
    std::string systemName;
    std::string systemDescription;

    LLDPData(timespec ts, pcpp::MacAddress mac, std::string port, std::string portDesc, std::string sysName, std::string sysDesc)
        : ProtocolData(ProtocolType::LLDP, ts), senderMAC(mac), portID(port), portDescription(portDesc), systemName(sysName), systemDescription(sysDesc) {}

    Json::Value toJson() const override {
        Json::Value jsonData = ProtocolData::toJson();  // ajoute les champs de base (timestamp, etc.)

        jsonData["SENDER_MAC"] = senderMAC.toString();
        jsonData["PORT_ID"] = portID;
        jsonData["PORT_DESCRIPTION"] = portDescription;
        jsonData["SYSTEM_NAME"] = systemName;
        jsonData["SYSTEM_DESCRIPTION"] = systemDescription;

        return jsonData;
    }
};

// Data structure for STP protocol
/**
 * @struct STPData
 * @brief Data structure for STP protocol.
 * 
 * The STPData struct is a data structure for storing STP protocol data.
 * It contains fields for the sender MAC address, root identifier, and bridge identifier.
 */
struct STPData : public ProtocolData {
    pcpp::MacAddress senderMAC;
    STPLayer::RootIdentifier rootIdentifier;
    STPLayer::BridgeIdentifier bridgeIdentifier;

    // Modified constructor to take an STPLayer object directly
    STPData(timespec ts, pcpp::MacAddress mac, STPLayer::RootIdentifier rootId, STPLayer::BridgeIdentifier bridgeId)
        : ProtocolData(ProtocolType::STP, ts),
            senderMAC(mac),  // Initialize from parameter
            rootIdentifier(rootId),  // Initialize from parameter
            bridgeIdentifier(bridgeId) {}  // Initialize from parameter
    
    Json::Value toJson() const override {
        Json::Value jsonData = ProtocolData::toJson();  // ajoute les champs de base (timestamp, etc.)

        jsonData["SENDER_MAC"] = senderMAC.toString();
        jsonData["ROOT_IDENTIFIER"]["PRIORITY"] = rootIdentifier.priority;
        jsonData["ROOT_IDENTIFIER"]["SYSTEM_ID_EXTENSION"] = rootIdentifier.systemIDExtension;
        jsonData["ROOT_IDENTIFIER"]["SYSTEM_ID"] = rootIdentifier.systemID;
        jsonData["BRIDGE_IDENTIFIER"]["PRIORITY"] = bridgeIdentifier.priority;
        jsonData["BRIDGE_IDENTIFIER"]["SYSTEM_ID_EXTENSION"] = bridgeIdentifier.systemIDExtension;
        jsonData["BRIDGE_IDENTIFIER"]["SYSTEM_ID"] = bridgeIdentifier.systemID;

        return jsonData;
    }
};

// Data structure for SSDP protocol
/**
 * @struct SSDPData
 * @brief Data structure for SSDP protocol.
 * 
 * The SSDPData struct is a data structure for storing SSDP protocol data.
 * It contains fields for the sender MAC address, sender IP address, SSDP type,
 * and SSDP headers.
 */
struct SSDPData : public ProtocolData {
    pcpp::MacAddress senderMAC;
    pcpp::IPv4Address senderIP;

    SSDPLayer::SSDPType ssdpType;
    std::vector<std::pair<std::string, std::string>> ssdpHeaders;

    SSDPData(timespec ts, pcpp::MacAddress mac, pcpp::IPv4Address ip, SSDPLayer::SSDPType type, std::vector<std::pair<std::string, std::string>> headers)
        : ProtocolData(ProtocolType::SSDP, ts), senderMAC(mac), senderIP(ip), ssdpType(type), ssdpHeaders(headers) {}

    Json::Value toJson() const override {
        Json::Value jsonData = ProtocolData::toJson();  // ajoute les champs de base (timestamp, etc.)

        jsonData["SENDER_MAC"] = senderMAC.toString();
        jsonData["SENDER_IP"] = senderIP.toString();
        jsonData["SSDP_TYPE"] = ssdpType == SSDPLayer::SSDPType::NOTIFY ? "NOTIFY" : "M-SEARCH";

        Json::Value headersJson;
        for (const auto& header : ssdpHeaders) {
            headersJson[header.first] = header.second;
        }
        jsonData["HEADERS"] = headersJson;

        return jsonData;
    }
};

// Data structure for CDP protocol
/**
 * @struct CDPData
 * @brief Data structure for CDP protocol.
 * 
 * The CDPData struct is a data structure for storing CDP protocol data.
 * It contains fields for the sender MAC address, sender IP address, device ID,
 * addresses, port ID, capabilities, software version, platform, VTP management domain,
 * native VLAN, duplex, trust bitmap, untrusted port CoS, and management addresses.
 */
struct CDPData : public ProtocolData {
    pcpp::MacAddress senderMAC;
    pcpp::IPv4Address senderIP;
    CDPLayer::DeviceId deviceId;
    CDPLayer::Addresses addresses;
    std::string portId;
    uint32_t capabilities;
    std::string capabilitiesStr;
    std::string softwareVersion;
    std::string platform;
    std::string vtpManagementDomain;
    uint16_t nativeVlan;
    uint8_t duplex;
    uint8_t trustBitmap;
    uint8_t untrustedPortCos;
    CDPLayer::Addresses mgmtAddresses;

    CDPData(timespec ts, pcpp::MacAddress mac, CDPLayer cdpLayer)
        : ProtocolData(ProtocolType::CDP, ts), senderMAC(mac), deviceId(cdpLayer.getDeviceId()), addresses(cdpLayer.getAddresses()), portId(cdpLayer.getPortId()), capabilities(cdpLayer.getCapabilities()), capabilitiesStr(cdpLayer.capabilitiesToString(cdpLayer.getCapabilities())), softwareVersion(cdpLayer.getSoftwareVersion()), platform(cdpLayer.getPlatform()), vtpManagementDomain(cdpLayer.getVTPManagementDomain()), nativeVlan(cdpLayer.getNativeVlan()), duplex(cdpLayer.getDuplex()), trustBitmap(cdpLayer.getTrustBitmap()), untrustedPortCos(cdpLayer.getUntrustedPortCos()), mgmtAddresses(cdpLayer.getMgmtAddresses()) {}

    Json::Value toJson() const override {
        Json::Value jsonData = ProtocolData::toJson();  // ajoute les champs de base (timestamp, etc.)

        jsonData["SENDER_MAC"] = senderMAC.toString();
        jsonData["DEVICE_ID"] = deviceId.id;
        jsonData["PORT_ID"] = portId;
        jsonData["CAPABILITIES"] = capabilitiesStr;
        jsonData["SOFTWARE_VERSION"] = softwareVersion;
        jsonData["PLATFORM"] = platform;
        jsonData["VTP_MANAGEMENT_DOMAIN"] = vtpManagementDomain;
        jsonData["NATIVE_VLAN"] = nativeVlan;
        jsonData["DUPLEX"] = duplex == 0 ? "Half" : "Full";
        jsonData["TRUST_BITMAP"] = trustBitmap;
        jsonData["UNTRUSTED_PORT_COS"] = untrustedPortCos;

        Json::Value addressesJson;
        for (const auto& address : addresses.addresses) {
            Json::Value addressJson;
            addressJson["PROTOCOL_TYPE"] = address.protocolType;
            addressJson["PROTOCOL_LENGTH"] = address.protocolLength;
            addressJson["PROTOCOL"] = address.protocol;
            addressJson["ADDRESS_LENGTH"] = address.addressLength;
            addressJson["ADDRESS"] = getAddressString(address);
            addressesJson.append(addressJson);
        }
        jsonData["ADDRESSES"] = addressesJson;

        Json::Value mgmtAddressesJson;
        for (const auto& mgmtAddress : mgmtAddresses.addresses) {
            Json::Value mgmtAddressJson;
            mgmtAddressJson["PROTOCOL_TYPE"] = mgmtAddress.protocolType;
            mgmtAddressJson["PROTOCOL_LENGTH"] = mgmtAddress.protocolLength;
            mgmtAddressJson["PROTOCOL"] = mgmtAddress.protocol;
            mgmtAddressJson["ADDRESS_LENGTH"] = mgmtAddress.addressLength;
            mgmtAddressJson["ADDRESS"] = getAddressString(mgmtAddress);
            mgmtAddressesJson.append(mgmtAddressJson);
        }
        jsonData["MGMT_ADDRESSES"] = mgmtAddressesJson;

        return jsonData;
    }
    std::string getAddressString(const CDPLayer::Address& address) const {
        std::string addressStr;
        for (size_t i = 0; i < address.addressLength; ++i) {
            addressStr += std::to_string(address.address[i]);
            if (i < address.addressLength - 1) {
                addressStr += ".";
            }
        }
        return addressStr;
    }
};

// Data structure for WOL protocol
/**
 * @struct WOLData
 * @brief Data structure for WOL protocol.
 * 
 * The WOLData struct is a data structure for storing WOL protocol data.
 * It contains fields for the sender MAC address and target MAC address.
 */
struct WOLData : public ProtocolData {
    pcpp::MacAddress senderMAC;
    pcpp::MacAddress targetMAC;

    WOLData(timespec ts, pcpp::MacAddress sender, pcpp::MacAddress target)
        : ProtocolData(ProtocolType::WOL, ts), senderMAC(sender), targetMAC(target) {}

    Json::Value toJson() const override {
        Json::Value jsonData = ProtocolData::toJson();  // ajoute les champs de base (timestamp, etc.)

        jsonData["SENDER_MAC"] = senderMAC.toString();
        jsonData["TARGET_MAC"] = targetMAC.toString();

        return jsonData;
    }
};

// Data structure for ICMP protocol
/**
 * @struct ICMPData
 * @brief Data structure for ICMP protocol.
 * 
 * The ICMPData struct is a data structure for storing ICMP protocol data.
 * It contains fields for the sender MAC address, sender IP address, and target IP address, and target MAC address, and ICMP message type.
 */
 struct ICMPData : public ProtocolData {
    pcpp::MacAddress senderMAC;
    pcpp::IPAddress senderIP;
    pcpp::MacAddress targetMAC; 
    pcpp::IPAddress targetIP; 
    uint8_t type;
    // Constructor
    ICMPData(timespec ts, pcpp::MacAddress mac, pcpp::IPAddress sender, pcpp::MacAddress targetMac, pcpp::IPAddress target, uint8_t icmpType)
        : ProtocolData(ProtocolType::ICMP, ts), senderMAC(mac), senderIP(sender), targetMAC(targetMac), targetIP(target), type(icmpType) {}
    Json::Value toJson() const override {
        Json::Value jsonData = ProtocolData::toJson();  // ajoute les champs de base (timestamp, etc.)

        jsonData["SENDER_MAC"] = senderMAC.toString();
        jsonData["SENDER_IP"] = senderIP.toString();
        jsonData["TARGET_MAC"] = targetMAC.toString();
        jsonData["TARGET_IP"] = targetIP.toString();
        jsonData["ICMP_TYPE"] = std::to_string(type);

        return jsonData;
    }
};

// Data structure for SNMP protocol
/**
 * @struct SNMPData
 * @brief Data structure for DNMP protocol.
 * 
 * The SNMPData struct is a data structure for storing SNMP protocol data.
 * It contains fields for the sender MAC address, sender IP address, and target IP address, and target MAC address, and SNMP message type.
 */
struct SNMPData : public ProtocolData {
    pcpp::MacAddress senderMAC;
    pcpp::IPAddress senderIP;
    pcpp::MacAddress targetMAC;
    pcpp::IPAddress targetIP;
    std::string type;
    std::string communityName;
    std::string oid;
    std::string oidName;
    std::string oidValue;
    std::string version;
    std::string errorStatus;
    // Constructor
    SNMPData(timespec ts, pcpp::MacAddress mac, pcpp::IPAddress sender, pcpp::MacAddress targetMac, pcpp::IPAddress target, std::string snmpType, std::string communityName, std::string oid, std::string oidName, std::string oidValue, std::string version, std::string errorStatus)
        : ProtocolData(ProtocolType::SNMP, ts), senderMAC(mac), senderIP(sender), targetMAC(targetMac), targetIP(target), type(snmpType), communityName(communityName), oid(oid), oidName(oidName), oidValue(oidValue), version(version), errorStatus(errorStatus) {}

    Json::Value toJson() const override {
        Json::Value jsonData = ProtocolData::toJson();  // ajoute les champs de base (timestamp, etc.)

        jsonData["SENDER_MAC"] = senderMAC.toString();
        jsonData["SENDER_IP"] = senderIP.toString();
        jsonData["TARGET_MAC"] = targetMAC.toString();
        jsonData["TARGET_IP"] = targetIP.toString();
        jsonData["SNMP_TYPE"] = type;
        jsonData["COMMUNITY_NAME"] = communityName;
        jsonData["OID"] = oid;
        jsonData["OID_NAME"] = oidName;
        jsonData["OID_VALUE"] = oidValue;
        jsonData["VERSION_SNMP"] = version;
        jsonData["ERROR_STATUS"] = errorStatus;

        return jsonData;
    }
};
/**
 * @struct ProtocolDataComparator
 * @brief Comparator for protocol data.
 * 
 * The ProtocolDataComparator struct provides a comparison function for protocol data.
 * It compares two unique pointers to ProtocolData objects based on the protocol type
 * and specific protocol data fields.
 * 
 * This comparator is used to compare protocol data objects in a set to ensure uniqueness.
 * It is used in the HostManager class to maintain a set of unique protocol data objects.
 * 
 */
struct ProtocolDataComparator {
    bool operator()(const std::unique_ptr<ProtocolData>& lhs, const std::unique_ptr<ProtocolData>& rhs) const {
        if (!lhs || !rhs) return false;

        // Compare by protocol type first
        if (lhs->getProtocolType() != rhs->getProtocolType()) {
            return lhs->getProtocolType() < rhs->getProtocolType();
        }

        // Cast and compare by specific protocol data fields, ignoring timestamp
        if (lhs->getProtocolType() == ProtocolType::DHCP) {
            const DHCPData* lhsData = static_cast<const DHCPData*>(lhs.get());
            const DHCPData* rhsData = static_cast<const DHCPData*>(rhs.get());
            return lhsData->clientMac != rhsData->clientMac || lhsData->ipAddress != rhsData->ipAddress || lhsData->hostname != rhsData->hostname ||
                   lhsData->dhcpServerIp != rhsData->dhcpServerIp || lhsData->gatewayIp != rhsData->gatewayIp || lhsData->dnsServerIp != rhsData->dnsServerIp;
        }

        if (lhs->getProtocolType() == ProtocolType::MDNS) {
            const mDNSData* lhsData = static_cast<const mDNSData*>(lhs.get());
            const mDNSData* rhsData = static_cast<const mDNSData*>(rhs.get());
            return lhsData->queriedDomain != rhsData->queriedDomain || lhsData->clientMac != rhsData->clientMac || lhsData->hostname != rhsData->hostname || lhsData->ipAddress != rhsData->ipAddress;
        }

        if (lhs->getProtocolType() == ProtocolType::ARP) {
            const ARPData* lhsData = static_cast<const ARPData*>(lhs.get());
            const ARPData* rhsData = static_cast<const ARPData*>(rhs.get());
            return lhsData->senderMac != rhsData->senderMac || lhsData->senderIp != rhsData->senderIp || lhsData->targetIp != rhsData->targetIp;
        }

        if (lhs->getProtocolType() == ProtocolType::STP) {
            const STPData* lhsData = static_cast<const STPData*>(lhs.get());
            const STPData* rhsData = static_cast<const STPData*>(rhs.get());
            return lhsData->senderMAC != rhsData->senderMAC || lhsData->rootIdentifier.priority != rhsData->rootIdentifier.priority ||
                   lhsData->rootIdentifier.systemIDExtension != rhsData->rootIdentifier.systemIDExtension || lhsData->rootIdentifier.systemID != rhsData->rootIdentifier.systemID ||
                   lhsData->bridgeIdentifier.priority != rhsData->bridgeIdentifier.priority || lhsData->bridgeIdentifier.systemIDExtension != rhsData->bridgeIdentifier.systemIDExtension ||
                   lhsData->bridgeIdentifier.systemID != rhsData->bridgeIdentifier.systemID;
        }

        if (lhs->getProtocolType() == ProtocolType::SSDP) {
    const SSDPData* lhsData = static_cast<const SSDPData*>(lhs.get());
    const SSDPData* rhsData = static_cast<const SSDPData*>(rhs.get());

    // Compare sender MAC and IP
    if (lhsData->senderMAC != rhsData->senderMAC || lhsData->senderIP != rhsData->senderIP) {
        return true;
    }

    // Compare ssdpHeaders as unordered sets
    std::unordered_multiset<std::pair<std::string, std::string>, PairHash> lhsHeaders(lhsData->ssdpHeaders.begin(), lhsData->ssdpHeaders.end());
    std::unordered_multiset<std::pair<std::string, std::string>, PairHash> rhsHeaders(rhsData->ssdpHeaders.begin(), rhsData->ssdpHeaders.end());

    if (lhsHeaders != rhsHeaders) {
        return true;
    }

    return false;
}

        if (lhs->getProtocolType() == ProtocolType::CDP) {
            const CDPData* lhsData = static_cast<const CDPData*>(lhs.get());
            const CDPData* rhsData = static_cast<const CDPData*>(rhs.get());
            // compare all addresses in the vector using the operator== defined above
            return lhsData->senderMAC != rhsData->senderMAC || lhsData->deviceId.subtype != rhsData->deviceId.subtype || lhsData->deviceId.id != rhsData->deviceId.id ||
                   lhsData->addresses.addresses.size() != rhsData->addresses.addresses.size() || !std::equal(lhsData->addresses.addresses.begin(), lhsData->addresses.addresses.end(), rhsData->addresses.addresses.begin()) ||
                     lhsData->portId != rhsData->portId || lhsData->capabilities != rhsData->capabilities || lhsData->capabilitiesStr != rhsData->capabilitiesStr ||
                        lhsData->softwareVersion != rhsData->softwareVersion || lhsData->platform != rhsData->platform || lhsData->vtpManagementDomain != rhsData->vtpManagementDomain ||
                        lhsData->nativeVlan != rhsData->nativeVlan || lhsData->duplex != rhsData->duplex || lhsData->trustBitmap != rhsData->trustBitmap || lhsData->untrustedPortCos != rhsData->untrustedPortCos ||
                        lhsData->mgmtAddresses.addresses.size() != rhsData->mgmtAddresses.addresses.size() || !std::equal(lhsData->mgmtAddresses.addresses.begin(), lhsData->mgmtAddresses.addresses.end(), rhsData->mgmtAddresses.addresses.begin());
        }

        if (lhs->getProtocolType() == ProtocolType::LLDP) {
            const LLDPData* lhsData = static_cast<const LLDPData*>(lhs.get());
            const LLDPData* rhsData = static_cast<const LLDPData*>(rhs.get());
            return lhsData->senderMAC != rhsData->senderMAC || lhsData->portID != rhsData->portID || lhsData->portDescription != rhsData->portDescription ||
                   lhsData->systemName != rhsData->systemName || lhsData->systemDescription != rhsData->systemDescription;
        }

        if (lhs->getProtocolType() == ProtocolType::WOL) {
            const WOLData* lhsData = static_cast<const WOLData*>(lhs.get());
            const WOLData* rhsData = static_cast<const WOLData*>(rhs.get());
            return lhsData->senderMAC != rhsData->senderMAC || lhsData->targetMAC != rhsData->targetMAC;
        }
        if (lhs->getProtocolType() == ProtocolType::ICMP) {
            const ICMPData* lhsData = static_cast<const ICMPData*>(lhs.get());
            const ICMPData* rhsData = static_cast<const ICMPData*>(rhs.get());
            return lhsData->senderMAC != rhsData->senderMAC || lhsData->senderIP != rhsData->senderIP || lhsData->targetIP != rhsData->targetIP || lhsData->type != rhsData->type;
        }
        if (lhs->getProtocolType() == ProtocolType::SNMP) {
            const SNMPData* lhsData = static_cast<const SNMPData*>(lhs.get());
            const SNMPData* rhsData = static_cast<const SNMPData*>(rhs.get());
            return lhsData->senderMAC != rhsData->senderMAC || lhsData->senderIP != rhsData->senderIP || lhsData->targetIP != rhsData->targetIP || lhsData->type != rhsData->type ||
                   lhsData->communityName != rhsData->communityName || lhsData->oid != rhsData->oid || lhsData->oidName != rhsData->oidName || lhsData->oidValue != rhsData->oidValue ||
                   lhsData->version != rhsData->version || lhsData->errorStatus != rhsData->errorStatus;
            }

        return false; // Fallback case
    }
};

// Add other protocol data structures as needed...

#endif // PROTOCOL_DATA_HPP
