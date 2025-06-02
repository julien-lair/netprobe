#ifndef DNS_ANALYZER_HPP
#define DNS_ANALYZER_HPP

#include "../Analyzer.hpp"

// DNSAnalyzer (Derived class)
/**
 * @class DNSAnalyzer
 * @brief Analyzes DNS packets and updates the host manager.
 * 
 * The DNSAnalyzer class is responsible for analyzing DNS packets and updating the host manager
 * with the DNS data. It extracts the DNS query name and response IP address from the DNS packet
 * and updates the host manager with this information.
 * 
 * The DNSAnalyzer class maintains a map of DNS query names to IP addresses to keep track of unique
 * addresses seen in the network.
 * 
 * The DNSAnalyzer class overrides the analyzePacket method from the base Analyzer class to handle DNS packets.
 */
class mDNSAnalyzer : public Analyzer {
    
public:
    mDNSAnalyzer(HostManager& hostManager) : Analyzer(hostManager) {}
    void analyzePacket(pcpp::Packet& parsedPacket) override;
};

#endif // DNS_ANALYZER_HPP