#include "ARPAnalyzer.hpp"

// Method to analyze a packet (overrides the virtual method in Analyzer)
void ARPAnalyzer::analyzePacket(pcpp::Packet& parsedPacket) {
    // Extract ARP layer
    pcpp::ArpLayer* arpLayer = parsedPacket.getLayerOfType<pcpp::ArpLayer>();
    if (arpLayer == nullptr) {
        return;
    }

    // Extract ARP source
    pcpp::MacAddress srcMac = arpLayer->getSenderMacAddress();
    pcpp::IPAddress srcIp = arpLayer->getSenderIpAddr();

    // Extract ARP destination
    pcpp::IPAddress dstIp = arpLayer->getTargetIpAddr();

    pcpp::RawPacket* rawPacket = parsedPacket.getRawPacket();
    timespec ts = rawPacket->getPacketTimeStamp();

    // Check if MAC and IP are valid

    if (srcMac == pcpp::MacAddress::Zero ||
        srcIp.isZero() || dstIp.isZero()) {
        return; // Invalid MAC or IP, exit the function
    }
    
    // Update the host manager with the ARP data
    auto arpData = std::make_unique<ARPData>(ts, srcMac, srcIp, dstIp);
    
    #ifdef DEBUG
    std::cout << "ARP Data:" << std::endl;
    std::cout << "\tSender MAC: " << arpData->senderMac << std::endl;
    std::cout << "\tSender IP: " << arpData->senderIp << std::endl;
    std::cout << "\tTarget IP: " << arpData->targetIp << std::endl;
    #endif
   
   hostManager.updateHost(ProtocolType::ARP, std::move(arpData));
}
