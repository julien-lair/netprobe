#include "WOLAnalyzer.hpp"

void WOLAnalyzer::analyzePacket(pcpp::Packet& parsedPacket) {
    // Check if the packet has Ethernet layer
    pcpp::EthLayer* ethLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    if (ethLayer == nullptr) {
        return; // No Ethernet layer, exit the function
    }
    // check if the packet is a WOL packet
    if (ethLayer->getEthHeader()->etherType != 0x4208) {
        return; // Not a WOL packet, exit
    }

    pcpp::RawPacket* rawPacket = parsedPacket.getRawPacket();
    timespec ts = rawPacket->getPacketTimeStamp();

    // Get the mac address of the source 
    pcpp::MacAddress sourceMacAddr = ethLayer->getSourceMac();

    // Get the mac address of the target in the WOL payload 
    pcpp::MacAddress targetMacAddrStr = pcpp::MacAddress(ethLayer->getLayerPayload() + 6);

    if (sourceMacAddr == pcpp::MacAddress::Zero || targetMacAddrStr == pcpp::MacAddress::Zero) {
        return; // Invalid IP or MAC, exit the function
    }
    
    // Create a WOLData object
    auto wolData = std::make_unique<WOLData>(ts, sourceMacAddr, targetMacAddrStr);
    
    #ifdef DEBUG
    std::cout << "WOL Data:" << std::endl;
    std::cout << "\tSource MAC: " << wolData->senderMAC << std::endl;
    std::cout << "\tTarget MAC: " << wolData->targetMAC << std::endl;
    #endif
    
    hostManager.updateHost(ProtocolType::WOL, std::move(wolData));
}