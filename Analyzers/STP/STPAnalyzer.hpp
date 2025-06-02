#ifndef STP_ANALYZER_HPP
#define STP_ANALYZER_HPP

#include "../Analyzer.hpp"
#include "../../Layers/STP/STPLayer.hpp"

#include <map>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <string>
#include <unordered_map> 

// LLDPAnalyzer class (derived from Analyzer)
/**
 * @class STPAnalyzer
 * @brief Analyzes STP packets and updates the host manager.
 * 
 * The STPAnalyzer class is responsible for analyzing STP packets and updating the host manager
 * with the STP data. It extracts the sender MAC address from the STP packet and updates the host manager
 * with this information.
 * 
 * The STPAnalyzer class maintains a map of sender MAC addresses to STP data to keep track of unique
 * addresses seen in the network.
 * 
 * The STPAnalyzer class overrides the analyzePacket method from the base Analyzer class to handle STP packets.
 */
class STPAnalyzer : public Analyzer {

public:
    STPAnalyzer(HostManager& hostManager) : Analyzer(hostManager) {}
    // Method to analyze a packet (overrides the virtual method in Analyzer)
    void analyzePacket(pcpp::Packet& parsedPacket) override;
};

#endif // LLDP_ANALYZER_HPP
