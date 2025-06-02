#include "ICMPAnalyzer.hpp"
#include "IcmpLayer.h"
#include "EthLayer.h"

void ICMPAnalyzer::analyzePacket(pcpp::Packet& parsedPacket) {
    // Extraire la couche ICMP
    pcpp::IcmpLayer* icmpLayer = parsedPacket.getLayerOfType<pcpp::IcmpLayer>();
    if (icmpLayer == nullptr) {
        return;
    }

    // Extraire les couches IP et Ethernet pour obtenir les adresses
    pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    pcpp::EthLayer* ethLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    if (ipLayer == nullptr || ethLayer == nullptr) {
        return;
    }

    // Récupération des adresses
    pcpp::MacAddress srcMac = ethLayer->getSourceMac();
    pcpp::MacAddress dstMac = ethLayer->getDestMac();
    pcpp::IPAddress srcIp = ipLayer->getSrcIPAddress();
    pcpp::IPAddress dstIp = ipLayer->getDstIPAddress();

    pcpp::RawPacket* rawPacket = parsedPacket.getRawPacket();
    timespec ts = rawPacket->getPacketTimeStamp();

    // Extraction des champs ICMP
    pcpp::IcmpMessageType type = icmpLayer->getMessageType();


    // Création de la structure ICMPData (à définir dans ton code)
    //vérifie mac et ip
    if (srcMac == pcpp::MacAddress::Zero || dstMac == pcpp::MacAddress::Zero ||
        srcIp.isZero() || dstIp.isZero()){    
        return; // Invalid MAC or IP, exit the function
    }
    auto icmpData = std::make_unique<ICMPData>(ts, srcMac, srcIp, dstMac, dstIp, type);

    #ifdef DEBUG
    std::cout << "ICMP Data:" << std::endl;
    std::cout << "\tSender MAC: " << icmpData->senderMAC << std::endl;
    std::cout << "\tTarget MAC: " << icmpData->targetMAC << std::endl;
    std::cout << "\tSender IP: " << icmpData->senderIP << std::endl;
    std::cout << "\tTarget IP: " << icmpData->targetIP << std::endl;
    std::cout << "\tICMP Type: " << static_cast<int>(icmpData->type) << std::endl;
    #endif

    hostManager.updateHost(ProtocolType::ICMP, std::move(icmpData));
}
