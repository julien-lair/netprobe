#include "mDNSAnalyzer.hpp"

void mDNSAnalyzer::analyzePacket(pcpp::Packet& parsedPacket) {
    // Check if the packet is Ethernet, IPv4, and UDP
    pcpp::EthLayer* ethLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
    pcpp::DnsLayer* dnsLayer = parsedPacket.getLayerOfType<pcpp::DnsLayer>();
    if (ethLayer == NULL || ipLayer == NULL || udpLayer == NULL) {
        return; // Not an Ethernet, IP, UDP, or DNS packet
    }

    // Check if the UDP packet is for mDNS (port 5353)
    uint16_t srcPort = ntohs(udpLayer->getUdpHeader()->portSrc);
    uint16_t dstPort = ntohs(udpLayer->getUdpHeader()->portDst);
    // std::cout << "mDNS maybe packet detected" << std::endl;
    // std::cout << "Source Port: " << srcPort << ", Destination Port: " << dstPort << std::endl;
    if (srcPort != 5353 && dstPort != 5353) {
        return; // Not an mDNS packet
    }//else{
    //     std::cout << "mDNS packet detected" << std::endl;
    //     return;
    // }

    pcpp::MacAddress srcMac = ethLayer->getSourceMac();
    std::string queriedDomain, hostname, ipAddress;
    // Extract the DNS queries/responses (assuming mDNS)
    if (dnsLayer->getQueryCount() > 0) {
        // Process DNS Queries (mDNS requests)
        for (pcpp::DnsQuery* query = dnsLayer->getFirstQuery(); query != NULL; query = dnsLayer->getNextQuery(query)) {
            queriedDomain = query->getName();
        }   
    }

    if (dnsLayer->getAnswerCount() > 0 && srcMac != pcpp::MacAddress::Zero) {
        // Process DNS Answers (mDNS responses)
        for (pcpp::DnsResource* answer = dnsLayer->getFirstAnswer(); answer != NULL; answer = dnsLayer->getNextAnswer(answer)) {
            if (answer->getDnsType() == pcpp::DNS_TYPE_A) { //DnsResourceType == DnsType

                hostname = answer->getName();
                ipAddress = answer->getData()->toString();
                
                pcpp::RawPacket* rawPacket = parsedPacket.getRawPacket();
                timespec ts = rawPacket->getPacketTimeStamp();  
                auto mdnsData = std::make_unique<mDNSData>(ts, queriedDomain, srcMac, hostname, ipAddress, "DNS_TYPE_A");
                hostManager.updateHost(ProtocolType::MDNS, std::move(mdnsData));
                #ifdef DEBUG
                std::cout << "mDNS A record detected" << std::endl;
                std::cout << "Queried Domain: " << queriedDomain << std::endl;
                std::cout << "Source MAC: " << srcMac.toString() << std::endl;
                std::cout << "Hostname: " << hostname << std::endl;
                std::cout << "IP Address: " << ipAddress << std::endl;
                #endif
            }else if(answer->getDnsType() == pcpp::DNS_TYPE_PTR){
                hostname = answer->getData()->toString();

                pcpp::RawPacket* rawPacket = parsedPacket.getRawPacket();
                timespec ts = rawPacket->getPacketTimeStamp();  
                auto mdnsData = std::make_unique<mDNSData>(ts, "", srcMac, hostname, pcpp::IPAddress("0.0.0.0"), "DNS_TYPE_PTR");

                hostManager.updateHost(ProtocolType::MDNS, std::move(mdnsData));
                #ifdef DEBUG
                std::cout << "mDNS PTR record detected" << std::endl;
                std::cout << "Queried Domain: " << queriedDomain << std::endl;
                std::cout << "Source MAC: " << srcMac.toString() << std::endl;
                std::cout << "Hostname: " << hostname << std::endl;
                std::cout << "IP Address: " << ipAddress << std::endl;
                #endif
            }else{
                return;
            }
        }
    }else{
        return; // No mDNS response or no source MAC address
    }
    

}
