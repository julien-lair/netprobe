#include "CDPAnalyzer.hpp"
#include "EthDot3Layer.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <pcap.h>
#include <cstring>
#include <arpa/inet.h>


const uint8_t CDP_MULTICAST_ADDR[6] = {0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc};

// Méthode pour analyser un paquet CDP
void CDPAnalyzer::analyzePacket(pcpp::Packet& parsedPacket) {
    
    pcpp::EthDot3Layer* ethLayer = parsedPacket.getLayerOfType<pcpp::EthDot3Layer>();
    if (ethLayer == nullptr) {
        return;
    }

    const uint8_t* payload = ethLayer->getLayerPayload();
    const size_t payloadSize = ethLayer->getLayerPayloadSize();
    const uint32_t logicalLinkControl = (payload[0] << 16 | payload[1] << 8 | payload[2]);
    uint16_t protocolID;
    // Check the DSAP and SSAP fields
    uint8_t dsap = payload[0];
    uint8_t ssap = payload[1];
    uint8_t control = payload[2];

    if (dsap == 0xAA && ssap == 0xAA && control == 0x03) {
        // This is an LLC+SNAP header
        uint32_t organizationCode = (payload[3] << 16) | (payload[4] << 8) | payload[5];
        protocolID = (payload[6] << 8) | payload[7];
    }

    if (protocolID != 0x2000) {
        return;
    }

    pcpp::RawPacket* rawPacket = parsedPacket.getRawPacket();
    timespec ts = rawPacket->getPacketTimeStamp();

    // Create CDPLayer 
    CDPLayer cdpLayer(payload + 12, payloadSize - 12);
    
    std::string ethLayerStr = ethLayer->toString();
    std::string srcPrefix = "Src: ";
    size_t srcPos = ethLayerStr.find(srcPrefix);
    size_t macStartPos = srcPos + srcPrefix.length();
    std::string srcMacStr = ethLayerStr.substr(macStartPos, 17);

    pcpp::MacAddress srcMac(srcMacStr);

    //check if mac is valid 
    if (srcMac == pcpp::MacAddress::Zero) {
        return; // Invalid MAC
    }
    
    auto cdpData = std::make_unique<CDPData>(ts, srcMac, cdpLayer);
    
    #ifdef DEBUG
    std::cout << "CDP Data:" << std::endl;
    std::cout << cdpLayer << std::endl;
    #endif
        
    hostManager.updateHost(ProtocolType::CDP, std::move(cdpData));
}

