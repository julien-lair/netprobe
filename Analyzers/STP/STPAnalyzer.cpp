#include "STPAnalyzer.hpp"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"
#include "EthDot3Layer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"


// Method to analyze a packet (overrides the virtual method in Analyzer)
void STPAnalyzer::analyzePacket(pcpp::Packet& parsedPacket) {
    // Check if the packet has Ethernet layer
    pcpp::EthDot3Layer* ethLayer = parsedPacket.getLayerOfType<pcpp::EthDot3Layer>();
    if (ethLayer == nullptr) {
        return; // No Ethernet layer, exit the function
    }

    const uint8_t* payload = ethLayer->getLayerPayload();
    const uint32_t logicalLinkControl = (payload[0] << 16 | payload[1] << 8 | payload[2]);
    const uint16_t protocolID = logicalLinkControl >> 8;

    if (protocolID != 0x4242) {
        return; // Not an STP packet, exit
    }

    pcpp::RawPacket* rawPacket = parsedPacket.getRawPacket();
    timespec ts = rawPacket->getPacketTimeStamp();

    STPLayer stplayer(payload + 6, ethLayer->getLayerPayloadSize() - 6);
    STPLayer::BridgeIdentifier bridgeIdentifier = stplayer.getBridgeIdentifier();
    STPLayer::RootIdentifier rootIdentifier = stplayer.getRootIdentifier();

    std::string ethLayerStr = ethLayer->toString();
    std::string srcPrefix = "Src: ";
    size_t srcPos = ethLayerStr.find(srcPrefix);
    size_t macStartPos = srcPos + srcPrefix.length();
    std::string srcMacStr = ethLayerStr.substr(macStartPos, 17);

    pcpp::MacAddress srcMac(srcMacStr);
    if (srcMac == pcpp::MacAddress::Zero) {
        return; // Invalid MAC
    }
    auto stpData = std::make_unique<STPData>(ts, srcMac, rootIdentifier, bridgeIdentifier);
    
    #ifdef DEBUG
    std::cout << "STP Data:" << std::endl;
    std::cout << stplayer << std::endl;
    #endif
    
    hostManager.updateHost(ProtocolType::STP, std::move(stpData));
}