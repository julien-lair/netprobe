#include "SNMPAnalyzer.hpp"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"

std::string snmpTypeToString(SNMPLayer::SNMPType type);
// Method to analyze a packet (overrides the virtual method in Analyzer) SNMP 
// Method to analyze a packet (overrides the virtual method in Analyzer) SNMP
void SNMPAnalyzer::analyzePacket(pcpp::Packet& parsedPacket) {
    // Check if the packet has Ethernet layer
    pcpp::EthLayer* ethLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();

    if (ethLayer == nullptr) {
        return; // No Ethernet layer, exit the function
    }

    // Now, check if the packet contains an IPv4 layer
    pcpp::IPv4Layer* ipv4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    if (ipv4Layer == nullptr) {
        return; // No IPv4 layer, exit the function
    }

    // Check if the packet contains a UDP layer (SNMP runs over UDP)
    pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
    if (udpLayer == nullptr) {
        return; // No UDP layer, exit the function
    }

    uint16_t srcPort = ntohs(udpLayer->getUdpHeader()->portSrc);
    uint16_t dstPort = ntohs(udpLayer->getUdpHeader()->portDst);

    // Check if the UDP port is the default SNMP port (161)
    if (srcPort != 161 && dstPort != 161) {
        //print the port 
        return; // Not an SNMP packet (not using port 161)
    }
    // If we've reached this point, it's likely an SNMP packet
    //std::cerr << "SNMP packet detected" << std::endl;

    // Create the SNMP layer from the raw data
    pcpp::RawPacket* rawPacket = parsedPacket.getRawPacket();
    timespec ts = rawPacket->getPacketTimeStamp();

    // Extract the sender MAC address and system name
    auto senderMac = ethLayer->getSourceMac();
    auto targetMac = ethLayer->getDestMac();

    // IP as string
    std::string senderIpStr = ipv4Layer->getSrcIPAddress().toString();
    std::string targetIpStr = ipv4Layer->getDstIPAddress().toString();

    // Extract SNMP data
    auto payload = udpLayer->getLayerPayload();
    auto payloadSize = udpLayer->getLayerPayloadSize();

    if (payload == nullptr || payloadSize == 0) {
        //std::cerr << "SNMP payload is empty or null!" << std::endl;
        return;
    }

    try {
        SNMPLayer snmpLayer(payload, payloadSize);
        SNMPLayer::SNMPType snmpType = snmpLayer.getType();
        std::string typeStr = snmpTypeToString(snmpType);
        std::string communityName = snmpLayer.getCommunityName();
        std::string versionStr;
        switch (snmpLayer.getVersion()) {
            case SNMPLayer::SNMP_V1: versionStr = "SNMP_V1"; break;
            case SNMPLayer::SNMP_V2C: versionStr = "SNMP_V2C"; break;
            case SNMPLayer::SNMP_V3: versionStr = "SNMP_V3"; break;
            default: versionStr = "UNKNOWN";
        }
        std::string errorStatusStr; 
        switch (snmpLayer.getErrorStatus()) {
            case SNMPLayer::NO_ERROR: errorStatusStr = "NO_ERROR"; break;
            case SNMPLayer::TOO_BIG: errorStatusStr = "TOO_BIG"; break;
            case SNMPLayer::NO_SUCH_NAME: errorStatusStr = "NO_SUCH_NAME"; break;
            case SNMPLayer::BAD_VALUE: errorStatusStr = "BAD_VALUE"; break;
            case SNMPLayer::READ_ONLY: errorStatusStr = "READ_ONLY"; break;
            case SNMPLayer::GENERIC_ERROR: errorStatusStr = "GENERIC_ERROR"; break;
            case SNMPLayer::NO_ACCESS: errorStatusStr = "NO_ACCESS"; break;
            case SNMPLayer::WRONG_TYPE: errorStatusStr = "WRONG_TYPE"; break;
            case SNMPLayer::WRONG_LENGTH: errorStatusStr = "WRONG_LENGTH"; break;
            case SNMPLayer::WRONG_ENCODING: errorStatusStr = "WRONG_ENCODING"; break;
            case SNMPLayer::WRONG_VALUE: errorStatusStr = "WRONG_VALUE"; break;
            case SNMPLayer::NO_CREATION: errorStatusStr = "NO_CREATION"; break;
            case SNMPLayer::INCONSISTENT_VALUE: errorStatusStr = "INCONSISTENT_VALUE"; break;
            case SNMPLayer::RESOURCE_UNAVAILABLE: errorStatusStr = "RESOURCE_UNAVAILABLE"; break;
            case SNMPLayer::COMMIT_FAILED: errorStatusStr = "COMMIT_FAILED"; break;
            case SNMPLayer::UNDO_FAILED: errorStatusStr = "UNDO_FAILED"; break;
            case SNMPLayer::AUTHORIZATION_ERROR: errorStatusStr = "AUTHORIZATION_ERROR"; break;
        }
        std::string oidStr;
        std::string oidNameStr;
        std::string oidValueStr;
        auto oids = snmpLayer.getOIDs();
        for (const auto& oid : oids) {
            oidStr = oid.oid;
            oidNameStr = oid.mibName;
            oidValueStr = oid.value;
        }
        //vérifie si les adresse IP sont correcte 
        if (senderIpStr.empty() || targetIpStr.empty()) {
            //std::cerr << "Invalid IP address!" << std::endl;
            return;
        }
        auto snmpData = std::make_unique<SNMPData>(ts, senderMac, senderIpStr, targetMac, targetIpStr, typeStr, communityName, oidStr,oidNameStr,oidValueStr, versionStr, errorStatusStr);

        #ifdef DEBUG
        std::cout << "SNMP Data:" << std::endl;
        std::cout << "\tSender MAC: " << snmpData->senderMAC << std::endl;
        std::cout << "\tSender IP: " << snmpData->senderIP << std::endl;
        std::cout << "\tTarget MAC: " << snmpData->targetMAC << std::endl;
        std::cout << "\tTarget IP: " << snmpData->targetIP << std::endl;
        std::cout << "\tSNMP Type: " << snmpData->type << std::endl;
        #endif
    
        hostManager.updateHost(ProtocolType::SNMP, std::move(snmpData));
    }
    catch (const std::exception& ex) {
        //std::cerr << "Failed to parse SNMP packet: " << ex.what() << std::endl;
        return;
    }
    
}

std::string snmpTypeToString(SNMPLayer::SNMPType type) {
    switch (type) {
        case SNMPLayer::GET_REQUEST: return "GET_REQUEST";
        case SNMPLayer::GET_NEXT_REQUEST: return "GET_NEXT_REQUEST";
        case SNMPLayer::GET_RESPONSE: return "GET_RESPONSE";
        case SNMPLayer::SET_REQUEST: return "SET_REQUEST";
        case SNMPLayer::TRAP_V1: return "TRAP_V1";
        case SNMPLayer::BULK_REQUEST: return "BULK_REQUEST";
        case SNMPLayer::INFORM_REQUEST: return "INFORM_REQUEST";
        case SNMPLayer::TRAP_V2: return "TRAP_V2";
        case SNMPLayer::REPORT: return "REPORT";
        default: return "UNKNOWN";
    }
}