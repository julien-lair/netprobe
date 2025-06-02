#include "SSDPLayer.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>

SSDPLayer::SSDPLayer(const uint8_t* data, size_t length)
  : rawData(data), rawDataLength(length) {
    parseSSDPDU();
}

void SSDPLayer::parseSSDPDU() {
  std::istringstream ss(std::string(reinterpret_cast<const char*>(rawData), rawDataLength));
  // Get the SSDP type reading the first line in ss 
  std::string firstLine;
  std::getline(ss, firstLine);

  if (firstLine.find("NOTIFY") != std::string::npos) {
    ssdpType = SSDPType::NOTIFY;
  } else if (firstLine.find("M-SEARCH") != std::string::npos) {
    ssdpType = SSDPType::MSEARCH;
  } 
  
  std::string line;
  while (std::getline(ss, line)) {
    size_t pos = line.find(':');
    if (pos != std::string::npos) {
      std::string key = line.substr(0, pos);
      std::string value = line.substr(pos + 1);
      ssdpHeaders.push_back(std::make_pair(key, value));
    }
  }
}

SSDPLayer::SSDPType SSDPLayer::getSSDPType() const {
  return ssdpType;
}

std::vector<std::pair<std::string, std::string>> SSDPLayer::getSSDPHeaders() const {
  return ssdpHeaders;
}

std::ostream& operator<<(std::ostream& os, const SSDPLayer& layer) {
  for (const auto& header : layer.ssdpHeaders) {
    os << header.first << ": " << header.second << std::endl;
  }

  return os;
}

