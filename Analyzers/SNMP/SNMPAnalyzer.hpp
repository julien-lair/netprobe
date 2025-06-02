#ifndef SNMP_ANALYZER_HPP
#define SNMP_ANALYZER_HPP

#include "../Analyzer.hpp"
#include "../../Layers/SNMP/SNMPLayer.hpp"

#include <map>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <string>
#include <unordered_map> 

// SNMPAnalyzer class (derived from Analyzer)
/**
 * @class SNMPAnalyzer
 * @brief Analyzes SNMP packets and updates the host manager.
 * 
* The SNMPAnalyzer class is responsible for analyzing SNMP packets and updating the host manager
* with the SNMP data. It extracts the sender MAC address, sender IP address, target IP address, and type 
* from the SNMP packet and updates the host manager with this information.
*
* The SNMPAnalyzer class maintains a map of sender MAC addresses to SNMP data to keep track of unique
* addresses seen in the network.
 * 
 * The SNMPAnalyzer class overrides the analyzePacket method from the base Analyzer class to handle SNMP packets.
 */
class SNMPAnalyzer : public Analyzer {

public:
    SNMPAnalyzer(HostManager& hostManager) : Analyzer(hostManager) {}
    // Method to analyze a packet (overrides the virtual method in Analyzer)
    void analyzePacket(pcpp::Packet& parsedPacket) override;
};

#endif // SNMP_ANALYZER_HPP
