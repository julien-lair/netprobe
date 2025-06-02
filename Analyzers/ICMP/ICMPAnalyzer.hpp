#ifndef ICMP_ANALYZER_HPP
#define ICMP_ANALYZER_HPP

#include "../Analyzer.hpp"

// ICMPAnalyzer class (derived from Analyzer)
/**
 * @class ICMPAnalyzer
 * @brief Analyzes ICMP packets and updates the host manager.
 * 
 * The ICMPAnalyzer class is responsible for analyzing ICMP packets and updating the host manager
 * with the ICMP data. It extracts the client MAC address, client IP address from the ICMP packet and updates the host manager with
 * this information.
 * 
 * The ICMPAnalyzer class maintains sets of client MAC addresses, client IP addresses,
  to keep track of unique addresses seen in the network.
 * 
 * The ICMPAnalyzer class overrides the analyzePacket method from the base Analyzer class to handle ICMP packets.
 * 
 */
class ICMPAnalyzer : public Analyzer {

public:
    ICMPAnalyzer(HostManager& hostManager) : Analyzer(hostManager) {}
    // Method to analyze a packet (overrides the virtual method in Analyzer)
    void analyzePacket(pcpp::Packet& parsedPacket) override;
    
};

#endif // ICMP_ANALYZER_HPP
