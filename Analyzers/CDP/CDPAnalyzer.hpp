#ifndef CDP_ANALYZER_H
#define CDP_ANALYZER_H

#include "../Analyzer.hpp"
#include "../../Layers/CDP/CDPLayer.hpp"

#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include <string>

class CDPAnalyzer : public Analyzer {
public:
    CDPAnalyzer(HostManager& hostManager) : Analyzer(hostManager) {}
    void analyzePacket(pcpp::Packet& parsedPacket) override;
};

#endif // CDP_ANALYZER_H
