#include "LLDPAnalyzer.hpp"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"


// Method to analyze a packet (overrides the virtual method in Analyzer)
void LLDPAnalyzer::analyzePacket(pcpp::Packet& parsedPacket) {
    // Check if the packet has Ethernet layer
    pcpp::EthLayer* ethLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    if (ethLayer == nullptr) {
        return; // No Ethernet layer, exit the function
    }

    // check if the packet is an LLDP packet
    if (ethLayer->getEthHeader()->etherType != 0x88cc) {
        return; // Not an LLDP packet, exit
    }
    pcpp::RawPacket* rawPacket = parsedPacket.getRawPacket();
    timespec ts = rawPacket->getPacketTimeStamp();

    // LLDP uses a special EtherType (0x88cc)
    LLDPLayer lldpLayer(ethLayer->getLayerPayload(), ethLayer->getLayerPayloadSize());

    // Extract the sender MAC address and system name
    pcpp::MacAddress senderMac = ethLayer->getSourceMac();
    std::string portID = lldpLayer.getPortId();
    std::string portDescription = lldpLayer.getPortDescription();
    std::string systemName = lldpLayer.getSystemName();
    std::string systemDescription = lldpLayer.getSystemDescription();

    // Create an LLDPData object
    //vérifie mac et ip
    if (senderMac == pcpp::MacAddress::Zero || portID.empty() || portDescription.empty() || systemName.empty()) {
        return; // Invalid MAC or IP, exit the function
    }    
    auto lldpData = std::make_unique<LLDPData>(ts, senderMac, portID, portDescription, systemName, systemDescription);
    
    #ifdef DEBUG
    std::cout << "LLDP Data:" << std::endl;
    std::cout << "\tSender MAC: " << lldpData->senderMAC << std::endl;
    std::cout << "\tPort ID: " << lldpData->portID << std::endl;
    std::cout << "\tPort Description: " << lldpData->portDescription << std::endl;
    std::cout << "\tSystem Name: " << lldpData->systemName << std::endl;
    std::cout << "\tSystem Description: " << lldpData->systemDescription << std::endl;
    #endif
    
    hostManager.updateHost(ProtocolType::LLDP, std::move(lldpData));
}
