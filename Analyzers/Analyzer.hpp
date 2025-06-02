#ifndef ANALYZER_HPP
#define ANALYZER_HPP


#include "PcapLiveDeviceList.h"
#include "PcapLiveDevice.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"
#include "DhcpLayer.h"
#include "DnsLayer.h"
#include "DnsResourceData.h"
#include "TcpLayer.h"
#include "MacAddress.h"
#include "../Hosts/HostManager.hpp"
#include <iostream>
#include <map>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <arpa/inet.h>
#include <unordered_set>

// Base Analyzer class
/**
 * @class Analyzer
 * @brief Abstract base class for analyzing network packets.
 *
 * The Analyzer class provides an interface for analyzing specific protocol packets.
 * Derived classes must implement the analyzePacket method to handle the analysis
 * of packets for different protocols.
 */

class Analyzer {
public:
    Analyzer(HostManager& hostManager) : hostManager(hostManager) {}
    virtual ~Analyzer() {}
    /**
    * @brief Analyzes a given packet.
    * 
    * This is a pure virtual function that must be implemented by derived classes.
    * 
    * @param packet Reference to a pcpp::Packet object to be analyzed.
    */
    virtual void analyzePacket(pcpp::Packet& packet) = 0;
protected:
    // Host manager reference
    HostManager& hostManager;
};

#endif // ANALYZER_HPP
