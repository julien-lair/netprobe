#ifndef WOL_ANALYZER_HPP
#define WOL_ANALYZER_HPP

#include "../Analyzer.hpp"

// WOLAnalyzer class (derived from Analyzer)
/**
 * @class WOLAnalyzer
 * @brief Analyzes Wake-on-LAN (WOL) packets and updates the host manager.
 * 
 * The WOLAnalyzer class is responsible for analyzing Wake-on-LAN (WOL) packets and updating the host manager
 * with the WOL data. It extracts the source and target MAC addresses from the WOL packet and updates the host manager
 * with this information.
 * 
 * The WOLAnalyzer class maintains sets of source and target MAC addresses to keep track of unique
 * addresses seen in the network.
 * 
 * The WOLAnalyzer class overrides the analyzePacket method from the base Analyzer class to handle WOL packets.
 */

class WOLAnalyzer : public Analyzer {
  public:
    WOLAnalyzer(HostManager& hostManager) : Analyzer(hostManager) {}
    void analyzePacket(pcpp::Packet& parsedPacket) override;
};

#endif // WOL_ANALYZER_HPP