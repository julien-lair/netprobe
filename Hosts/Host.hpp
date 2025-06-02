#ifndef HOST_HPP
#define HOST_HPP

#include "MacAddress.h"
#include "IPv4Layer.h"
#include "ProtocolData.hpp"

#include <string>
#include <unordered_map>
#include <ctime>
#include <iostream>
#include <fstream>
#include <array>
#include <set>
#include <json/json.h>
#include <boost/algorithm/string.hpp>

void loadVendorDatabase(const std::string& filename, std::map<std::string, std::string>& vendorDatabase);
void swapMacBytes(std::string& mac);
std::string getVendorName(const std::string& macPrefix, const std::map<std::string, std::string>& vendorDatabase);
std::string pcppMACAddressToString(const pcpp::MacAddress& mac, const std::map<std::string, std::string>& vendorDatabase);

extern std::map<std::string, std::string> vendorDatabase;

/**
 * @class Host
 * 
 * @brief Represents a network host.
 * 
 * The Host class represents a network host with a MAC address, IP address, hostname, and protocol data.
 * It provides methods to update and retrieve host information, as well as to convert host data to JSON format.
 * 
 * The Host class also provides methods to update and retrieve protocol-specific data for a host.
 */
class Host {
  public:
    Host() : mac_address(pcpp::MacAddress::Zero), ip_address(pcpp::IPv4Address::Zero), host_name("") {}
    Host(const pcpp::MacAddress& mac, const pcpp::IPAddress& ip = pcpp::IPv4Address::Zero, const std::string& hostname = "", const timespec& first = timespec(), const timespec& last = timespec())
      : ip_address(ip), mac_address(mac), host_name(hostname), first_seen(first), last_seen(last) {}

    // Move constructor
    Host(Host&& other) noexcept
        : ip_address(std::move(other.ip_address)),
          mac_address(std::move(other.mac_address)),
          host_name(std::move(other.host_name)),
          first_seen(other.first_seen),
          last_seen(other.last_seen),
          protocols_data(std::move(other.protocols_data)) {}

    // Move assignment operator
    Host& operator=(Host&& other) noexcept {
        if (this != &other) {
            ip_address = std::move(other.ip_address);
            mac_address = std::move(other.mac_address);
            host_name = std::move(other.host_name);
            first_seen = other.first_seen;
            last_seen = other.last_seen;
            protocols_data = std::move(other.protocols_data);
        }
        return *this;
    }

    // Getters
    pcpp::IPAddress getIPAddress() const { return ip_address; }
    pcpp::MacAddress getMACAddress() const { return mac_address; }
    std::string getHostName() const { return host_name; }
    timespec getFirstSeen() const { return first_seen; }
    timespec getLastSeen() const { return last_seen; }

    // Setters                  
    void setIPAddress(const pcpp::IPAddress& ip) { ip_address = ip; }
    void setMACAddress(const pcpp::MacAddress& mac) { mac_address = mac; }
    void setHostName(const std::string& hostname) { host_name = hostname; }
    void setFirstSeen(const timespec& first) { first_seen = first; }
    void setLastSeen(const timespec& last) { last_seen = last; }
    void getProtocolData(ProtocolType protocol, ProtocolData& data) const;
    void updateProtocolData(ProtocolType protocol, std::unique_ptr<ProtocolData> data);
    void editProtocolData(ProtocolType protocol, std::unique_ptr<ProtocolData> prev_data, std::unique_ptr<ProtocolData> new_data);

    // Date to string
    std::string dateToString(const timespec& ts) const {
        char buffer[80];
        struct tm t;
        localtime_r(&ts.tv_sec, &t);
        strftime(buffer, sizeof(buffer), "%d-%m-%Y %H:%M:%S", &t);
        return std::string(buffer);
    }
    

    Json::Value toJson() const {
        Json::Value hostJson;
        hostJson["MAC"] = pcppMACAddressToString(mac_address, vendorDatabase);
        hostJson["IP"] = (ip_address == pcpp::IPv4Address::Zero) ? "" : ip_address.toString();
        hostJson["HOSTNAME"] = host_name;
        hostJson["VENDOR"] = getVendorName(mac_address.toString().substr(0, 8), vendorDatabase);
        hostJson["FIRST SEEN"] = dateToString(first_seen);
        hostJson["LAST SEEN"] = dateToString(last_seen);

        Json::Value protocolsJson;
        for (const auto& protocolDataVector : protocols_data) {
            for (const auto& protocolDataPtr : protocolDataVector) {
                if (!protocolDataPtr) {
                    continue; // Skip uninitialized or empty protocol data slots
                }
                ProtocolData* protocol_data = protocolDataPtr.get();
                if (protocol_data->protocol == ProtocolType::DHCP) {
                    DHCPData* dhcp_data = static_cast<DHCPData*>(protocol_data);
                    Json::Value dhcpJson;
                    dhcpJson["TIMESTAMP"] = dateToString(dhcp_data->timestamp);
                    dhcpJson["CLIENT MAC"] = dhcp_data->clientMac.toString();
                    dhcpJson["IP"] = dhcp_data->ipAddress.toString();
                    dhcpJson["HOSTNAME"] = dhcp_data->hostname;
                    dhcpJson["DHCP SERVER IP"] = dhcp_data->dhcpServerIp.toString();
                    dhcpJson["GATEWAY IP"] = dhcp_data->gatewayIp.toString();
                    dhcpJson["DNS SERVER IP"] = dhcp_data->dnsServerIp.toString();
                    protocolsJson["DHCP"].append(dhcpJson);
                }
                else if (protocol_data->protocol == ProtocolType::ARP) {
                    ARPData* arp_data = static_cast<ARPData*>(protocol_data);
                    Json::Value arpJson;
                    arpJson["TIMESTAMP"] = dateToString(arp_data->timestamp);
                    arpJson["SENDER MAC"] = arp_data->senderMac.toString();
                    arpJson["SENDER IP"] = arp_data->senderIp.toString();
                    arpJson["TARGET IP"] = arp_data->targetIp.toString();
                    protocolsJson["ARP"].append(arpJson);
                }
                else if (protocol_data->protocol == ProtocolType::LLDP) {
                    LLDPData* lldp_data = static_cast<LLDPData*>(protocol_data);
                    Json::Value lldpJson;
                    lldpJson["TIMESTAMP"] = dateToString(lldp_data->timestamp);
                    lldpJson["SENDER MAC"] = lldp_data->senderMAC.toString();
                    lldpJson["PORT ID"] = lldp_data->portID;
                    lldpJson["PORT DESCRIPTION"] = lldp_data->portDescription;
                    lldpJson["SYSTEM NAME"] = lldp_data->systemName;
                    lldpJson["SYSTEM DESCRIPTION"] = lldp_data->systemDescription;
                    protocolsJson["LLDP"].append(lldpJson);
                }
                else if (protocol_data->protocol == ProtocolType::STP) {
                    STPData* stp_data = static_cast<STPData*>(protocol_data);
                    Json::Value stpJson;
                    stpJson["TIMESTAMP"] = dateToString(stp_data->timestamp);
                    stpJson["SENDER MAC"] = stp_data->senderMAC.toString();
                    uint16_t reversedRootIdentifier = reverseBytes16(stp_data->rootIdentifier.priority);
                    stpJson["ROOT IDENTIFIER"]["PRIORITY"] = reversedRootIdentifier;
                    stpJson["ROOT IDENTIFIER"]["SYSTEM ID EXTENSION"] = stp_data->rootIdentifier.systemIDExtension;
                    uint64_t reversedRootSystemID = reverseBytes48(stp_data->rootIdentifier.systemID);
                    stpJson["ROOT IDENTIFIER"]["SYSTEM ID"] = pcpp::MacAddress(reinterpret_cast<uint8_t*>(&reversedRootSystemID)).toString();
                    uint16_t reversedBridgeIdentifier = reverseBytes16(stp_data->bridgeIdentifier.priority);
                    stpJson["BRIDGE IDENTIFIER"]["PRIORITY"] = reversedBridgeIdentifier;
                    stpJson["BRIDGE IDENTIFIER"]["SYSTEM ID EXTENSION"] = stp_data->bridgeIdentifier.systemIDExtension;
                    uint64_t reversedBridgeSystemID = reverseBytes48(stp_data->bridgeIdentifier.systemID);
                    stpJson["BRIDGE IDENTIFIER"]["SYSTEM ID"] = pcpp::MacAddress(reinterpret_cast<uint8_t*>(&reversedBridgeSystemID)).toString();
                    protocolsJson["STP"].append(stpJson);
                }
                else if (protocol_data->protocol == ProtocolType::SSDP) {
                    SSDPData* ssdp_data = static_cast<SSDPData*>(protocol_data);
                    Json::Value ssdpJson;
                    ssdpJson["TIMESTAMP"] = dateToString(ssdp_data->timestamp);
                    ssdpJson["TYPE"] = ssdp_data->ssdpType == SSDPLayer::SSDPType::NOTIFY ? "NOTIFY" : "M-SEARCH";
                    Json::Value headersJson;
                    for (const auto& header : ssdp_data->ssdpHeaders) {
                        headersJson[header.first] = header.second;
                    }
                    ssdpJson["HEADERS"] = headersJson;
                    protocolsJson["SSDP"].append(ssdpJson);
                }
                else if (protocol_data->protocol == ProtocolType::CDP) {
                    CDPData* cdp_data = static_cast<CDPData*>(protocol_data);
                    Json::Value cdpJson;
                    cdpJson["TIMESTAMP"] = dateToString(cdp_data->timestamp);
                    cdpJson["DEVICE ID"] = cdp_data->deviceId.id;
                    Json::Value addressesJson;
                    for (const auto& address : cdp_data->addresses.addresses) {
                        Json::Value addressJson;
                        addressJson["PROTOCOL TYPE"] = address.protocolType;
                        addressJson["PROTOCOL LENGTH"] = address.protocolLength;
                        addressJson["PROTOCOL"] = address.protocol;
                        addressJson["ADDRESS LENGTH"] = address.addressLength;
                        addressJson["ADDRESS"] = getAddressString(address);
                        addressesJson.append(addressJson);
                    }
                    cdpJson["ADDRESSES"] = addressesJson;
                    cdpJson["PORT ID"] = cdp_data->portId;
                    cdpJson["CAPABILITIES"] = cdp_data->capabilitiesStr;
                    cdpJson["SOFTWARE VERSION"] = cdp_data->softwareVersion;
                    cdpJson["PLATFORM"] = cdp_data->platform;
                    cdpJson["VTP MANAGEMENT DOMAIN"] = cdp_data->vtpManagementDomain;
                    cdpJson["NATIVE VLAN"] = cdp_data->nativeVlan;
                    cdpJson["DUPLEX"] = cdp_data->duplex == 0 ? "Half" : "Full";
                    cdpJson["TRUST BITMAP"] = cdp_data->trustBitmap;
                    cdpJson["UNTRUSTED PORT COS"] = cdp_data->untrustedPortCos;
                    Json::Value mgmtAddressesJson;
                    for (const auto& mgmtAddress : cdp_data->mgmtAddresses.addresses) {
                        Json::Value mgmtAddressJson;
                        mgmtAddressJson["PROTOCOL TYPE"] = mgmtAddress.protocolType;
                        mgmtAddressJson["PROTOCOL LENGTH"] = mgmtAddress.protocolLength;
                        mgmtAddressJson["PROTOCOL"] = mgmtAddress.protocol;
                        mgmtAddressJson["ADDRESS LENGTH"] = mgmtAddress.addressLength;
                        mgmtAddressJson["ADDRESS"] = getAddressString(mgmtAddress);
                        mgmtAddressesJson.append(mgmtAddressJson);
                    }
                    cdpJson["MGMT ADDRESSES"] = mgmtAddressesJson;
                    protocolsJson["CDP"].append(cdpJson);
                }
                else if (protocol_data->protocol == ProtocolType::WOL) {
                    WOLData* wol_data = static_cast<WOLData*>(protocol_data);
                    Json::Value wolJson;
                    wolJson["TIMESTAMP"] = dateToString(wol_data->timestamp);
                    wolJson["SENDER MAC"] = wol_data->senderMAC.toString();
                    wolJson["TARGET MAC"] = wol_data->targetMAC.toString();
                    protocolsJson["WOL"].append(wolJson);
                }
                else if (protocol_data->protocol == ProtocolType::ICMP) {
                    ICMPData* icmp_data = static_cast<ICMPData*>(protocol_data);
                    Json::Value icmpJson;
                    icmpJson["TIMESTAMP"] = dateToString(icmp_data->timestamp);
                    icmpJson["SENDER MAC"] = icmp_data->senderMAC.toString();
                    icmpJson["SENDER IP"] = icmp_data->senderIP.toString();
                    icmpJson["TARGET MAC"] = icmp_data->targetMAC.toString();
                    icmpJson["TARGET IP"] = icmp_data->targetIP.toString();
                    icmpJson["ICMP TYPE"] = std::to_string(icmp_data->type);

                    protocolsJson["ICMP"].append(icmpJson);
                }
                else if (protocol_data->protocol == ProtocolType::SNMP) {
                    SNMPData* snmp_data = static_cast<SNMPData*>(protocol_data);
                    Json::Value snmpJson;
                    snmpJson["TIMESTAMP"] = dateToString(snmp_data->timestamp);
                    snmpJson["SENDER MAC"] = snmp_data->senderMAC.toString();
                    snmpJson["SENDER IP"] = snmp_data->senderIP.toString();
                    snmpJson["TARGET MAC"] = snmp_data->targetMAC.toString();
                    snmpJson["TARGET IP"] = snmp_data->targetIP.toString();
                    snmpJson["SNMP TYPE"] = snmp_data->type;
                    snmpJson["COMMUNITY NAME"] = snmp_data->communityName;
                    snmpJson["OID"] = snmp_data->oid;
                    snmpJson["OID NAME"] = snmp_data->oidName;
                    snmpJson["OID VALUE"] = snmp_data->oidValue;
                    snmpJson["VERSION SNMP"] = snmp_data->version;
                    snmpJson["ERROR STATUS"] = snmp_data->errorStatus;


                    protocolsJson["SNMP"].append(snmpJson);
                }
            }
        }

        hostJson["PROTOCOLS"] = protocolsJson;

        return hostJson;
    }

    // Overload the << operator to print the host information
    friend std::ostream& operator<<(std::ostream& os, const Host& host) {
        os << "IP Address: " << host.ip_address << std::endl;
        os << "MAC Address: " << pcppMACAddressToString(host.mac_address, vendorDatabase) << std::endl;
        os << "Host Name: " << host.host_name << std::endl;
        os << "First Seen: " << host.dateToString(host.first_seen) << std::endl;
        os << "Last Seen: " << host.dateToString(host.last_seen) << std::endl;
        
        // Print the protocols data
        for (const auto& protocolDataVector : host.protocols_data) {
            for (const auto& protocolDataPtr : protocolDataVector) {
                if (!protocolDataPtr) {
                    continue; // Skip uninitialized or empty protocol data slots
                }   
                ProtocolData* protocol_data = protocolDataPtr.get();
                if (protocol_data->protocol == ProtocolType::DHCP) {
                    DHCPData* dhcp_data = static_cast<DHCPData*>(protocol_data);
                    os << "DHCP Data:" << std::endl;
                    os << "\tTimestamp: " << host.dateToString(dhcp_data->timestamp) << std::endl;
                    os << "\tClient MAC: " << dhcp_data->clientMac << std::endl;
                    os << "\tIP Address: " << dhcp_data->ipAddress << std::endl;
                    os << "\tHostname: " << dhcp_data->hostname << std::endl;
                    os << "\tDHCP Server IP: " << dhcp_data->dhcpServerIp << std::endl;
                    os << "\tGateway IP: " << dhcp_data->gatewayIp << std::endl;
                    os << "\tDNS Server IP: " << dhcp_data->dnsServerIp << std::endl;
                }
                else if (protocol_data->protocol == ProtocolType::ARP) {
                    ARPData* arp_data = static_cast<ARPData*>(protocol_data);
                    os << "ARP Data:" << std::endl;
                    os << "\tTimestamp: " << host.dateToString(arp_data->timestamp) << std::endl;
                    os << "\tSender MAC: " << arp_data->senderMac << std::endl;
                    os << "\tSender IP: " << arp_data->senderIp << std::endl;
                    os << "\target IP: " << arp_data->targetIp << std::endl;
                }
                else if (protocol_data->protocol == ProtocolType::STP) {
                    STPData* stp_data = static_cast<STPData*>(protocol_data);
                    os << "STP Data:" << std::endl;
                    os << "\tTimestamp: " << host.dateToString(stp_data->timestamp) << std::endl;
                    os << "\tRoot Identifier:" << std::endl;
                    uint16_t reversedRootIdentifier = reverseBytes16(stp_data->rootIdentifier.priority);
                    os << "\t\tPriority: " << std::dec << reversedRootIdentifier << std::endl;
                    os << "\t\tSystem ID Extension: " << std::dec << int(stp_data->rootIdentifier.systemIDExtension) << std::endl;
                    uint64_t reversedSystemID = reverseBytes48(stp_data->rootIdentifier.systemID);
                    // Only print the 6 bytes first of the system ID
                    os << "\t\tSystem ID: " << std::hex << std::setfill('0');
                    os << std::setw(2) << ((reversedSystemID >> 40) & 0xFF) << ":";
                    os << std::setw(2) << ((reversedSystemID >> 32) & 0xFF) << ":";
                    os << std::setw(2) << ((reversedSystemID >> 24) & 0xFF) << ":";
                    os << std::setw(2) << ((reversedSystemID >> 16) & 0xFF) << ":";
                    os << std::setw(2) << ((reversedSystemID >> 8) & 0xFF) << ":";
                    os << std::setw(2) << (reversedSystemID & 0xFF) << std::endl;

                    os << "\tBridge Identifier:" << std::endl;
                    uint16_t reversedBridgeIdentifier = reverseBytes16(stp_data->bridgeIdentifier.priority);
                    os << "\t\tPriority: " << std::dec << reversedBridgeIdentifier << std::endl;
                    os << "\t\tSystem ID Extension: " << std::dec << int(stp_data->bridgeIdentifier.systemIDExtension) << std::endl;
                    uint64_t reversedBridgeSystemID = reverseBytes48(stp_data->bridgeIdentifier.systemID);
                    // Only print the 6 bytes first of the system ID
                    os << "\t\tSystem ID: " << std::hex << std::setfill('0');
                    os << std::setw(2) << ((reversedBridgeSystemID >> 40) & 0xFF) << ":";
                    os << std::setw(2) << ((reversedBridgeSystemID >> 32) & 0xFF) << ":";
                    os << std::setw(2) << ((reversedBridgeSystemID >> 24) & 0xFF) << ":";
                    os << std::setw(2) << ((reversedBridgeSystemID >> 16) & 0xFF) << ":";
                    os << std::setw(2) << ((reversedBridgeSystemID >> 8) & 0xFF) << ":";
                    os << std::setw(2) << (reversedBridgeSystemID & 0xFF) << std::endl;
                }else if (protocol_data->protocol == ProtocolType::ICMP) {
                    ICMPData* icmp_data = static_cast<ICMPData*>(protocol_data);
                    os << "ICMP Data:" << std::endl;
                    //os << "\tTimestamp: " << host.dateToString(icmp_data->timestamp) << std::endl;
                    //os << "\tSender MAC: " << icmp_data->senderMAC << std::endl;
                    //os << "\tSender IP: " << icmp_data->senderIP << std::endl;
                    //os << "\tTarget MAC: " << icmp_data->targetMAC << std::endl;
                    //os << "\tTarget IP: " << icmp_data->targetIP << std::endl;
                    //os << "\tICMP Type: " << std::to_string(icmp_data->type) << std::endl;
                }else if (protocol_data->protocol == ProtocolType::SNMP) {
                    SNMPData* snmp_data = static_cast<SNMPData*>(protocol_data);
                    os << "SNMP Data:" << std::endl;
                    os << "\tTimestamp: " << host.dateToString(snmp_data->timestamp) << std::endl;
                    os << "\tSender MAC: " << snmp_data->senderMAC << std::endl;
                    os << "\tSender IP: " << snmp_data->senderIP << std::endl;
                    os << "\tTarget MAC: " << snmp_data->targetMAC << std::endl;
                    os << "\tTarget IP: " << snmp_data->targetIP << std::endl;
                    os << "\tSNMP Type: " << snmp_data->type << std::endl;
                }
            }
        }
        return os;
    }

  private:
    pcpp::IPAddress ip_address;
    pcpp::MacAddress mac_address;
    std::string host_name;
    // First time seen
    timespec first_seen;
    // Last time seen
    timespec last_seen;
    // Array to store the protocols infos 
    std::array<std::set<std::unique_ptr<ProtocolData>, ProtocolDataComparator>, 10> protocols_data; //HERE CHANGE THE NUMBER OF PROTOCOLS

    // Delete copy constructor and copy assignment operator
    Host(const Host&) = delete;
    Host& operator=(const Host&) = delete;
};                                                                                                                                    

#endif // HOST_HPP