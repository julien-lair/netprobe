#ifndef LLDP_ANALYZER_HPP
#define LLDP_ANALYZER_HPP

#include "../Analyzer.hpp"
#include "../../Layers/LLDP/LLDPLayer.hpp"

#include <map>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <string>
#include <unordered_map> 

// LLDPAnalyzer class (derived from Analyzer)
/**
 * @class LLDPAnalyzer
 * @brief Analyzes LLDP packets and updates the host manager.
 * 
 * The LLDPAnalyzer class is responsible for analyzing LLDP packets and updating the host manager
 * with the LLDP data. It extracts the sender MAC address, sender port ID, and system name
 * from the LLDP packet and updates the host manager with this information.
 * 
 * The LLDPAnalyzer class maintains a map of sender MAC addresses to LLDP data to keep track of unique
 * addresses seen in the network.
 * 
 * The LLDPAnalyzer class overrides the analyzePacket method from the base Analyzer class to handle LLDP packets.
 */
class LLDPAnalyzer : public Analyzer {

public:
    LLDPAnalyzer(HostManager& hostManager) : Analyzer(hostManager) {}
    // Method to analyze a packet (overrides the virtual method in Analyzer)
    void analyzePacket(pcpp::Packet& parsedPacket) override;
};

#endif // LLDP_ANALYZER_HPP
