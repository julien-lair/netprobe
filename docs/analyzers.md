# Adding a New Analyzer to the Codebase

To add a new analyzer to the NetProbe codebase, follow these steps:

## 1. Create the Layer

The Layer class is responsible for parsing and representing the protocol data from the network packets. Create a new layer class in the appropriate directory under `Layers/`. For example, if you are adding support for a new protocol called XYZ, create `XYZLayer.hpp` and `XYZLayer.cpp`.

### Example: `Layers/XYZ/XYZLayer.hpp`

```hpp
#ifndef XYZ_LAYER_HPP
#define XYZ_LAYER_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <ostream>

class XYZLayer {
public:
	XYZLayer(const uint8_t* data, size_t length);
	// Add methods to parse and access XYZ protocol data
private:
	const uint8_t* rawData;
	size_t rawDataLength;
	// Add members to store parsed XYZ data
	void parseXYZDU();
};

#endif // XYZ_LAYER_HPP
```

### Example: `Layers/XYZ/XYZLayer.cpp`

```cpp
#include "XYZLayer.hpp"

XYZLayer::XYZLayer(const uint8_t* data, size_t length)
  : rawData(data), rawDataLength(length) {
	parseXYZDU();
}

void XYZLayer::parseXYZDU() {
	// Implement parsing logic for XYZ protocol
}
```

## 2. Create the Protocol Data Structure

The ProtocolData structure stores the parsed data for the new protocol. Create a new struct in `Hosts/ProtocolData.hpp`.

### Example: `Hosts/ProtocolData.hpp`

```hpp
struct XYZData : public ProtocolData {
	// Add fields to store XYZ protocol data
	XYZData(timespec ts, /* other parameters */)
		: ProtocolData(ProtocolType::XYZ, ts) {
		// Initialize fields
	}
};
```

## 3. Update the Host Class

The Host class manages the protocol data for each host. Update the `Host` class to handle the new protocol.

### Example: `Hosts/Host.hpp`

```hpp
class Host {
public:
	Json::Value toJson() const {
		// Add logic to convert XYZData to JSON
		if (protocol_data->protocol == ProtocolType::XYZ) {
			XYZData* xyz_data = static_cast<XYZData*>(protocol_data);
			Json::Value xyzJson;
			// Populate xyzJson with XYZData fields
			protocolsJson["XYZ"].append(xyzJson);
		}
	}
};
```

## 4. Create the Analyzer

The Analyzer class processes the packets and extracts the protocol data. Create a new analyzer class in the appropriate directory under `Analyzers/`.

### Example: `Analyzers/XYZ/XYZAnalyzer.hpp`

```hpp
#ifndef XYZ_ANALYZER_HPP
#define XYZ_ANALYZER_HPP

#include "../Analyzer.hpp"
#include "../../Layers/XYZ/XYZLayer.hpp"

class XYZAnalyzer : public Analyzer {
public:
	XYZAnalyzer(HostManager& hostManager) : Analyzer(hostManager) {}
	void analyzePacket(pcpp::Packet& parsedPacket) override;
};

#endif // XYZ_ANALYZER_HPP
```

### Example: `Analyzers/XYZ/XYZAnalyzer.cpp`

```cpp
#include "XYZAnalyzer.hpp"

void XYZAnalyzer::analyzePacket(pcpp::Packet& parsedPacket) {
	// Extract XYZ layer from the packet
	XYZLayer xyzLayer(parsedPacket.getRawData(), parsedPacket.getRawDataLen());
	// Create XYZData object
	auto xyzData = std::make_unique<XYZData>(/* parameters */);
	// Update the host manager with the XYZ data
	hostManager.updateHost(ProtocolType::XYZ, std::move(xyzData));
}
```

## 5. Update the Host Manager

The HostManager class updates the host information with the new protocol data. Update the `updateHost` method to handle the new protocol.

### Example: `Hosts/HostManager.cpp`

```cpp
void HostManager::updateHost(ProtocolType protocol, std::unique_ptr<ProtocolData> data) {
	switch (protocol) {
		case ProtocolType::XYZ: {
			XYZData* xyzData = dynamic_cast<XYZData*>(data.get());
			if (xyzData) {
				processHost(xyzData->senderMAC, xyzData->senderIP, "", ProtocolType::XYZ);
			}
			break;
		}
		// Handle other protocols
	}
}
```

## 6. Register the Analyzer

Finally, register the new analyzer in the main application.

### Example: `main.cpp`

```cpp
int main() {
	// Create an instance of the new analyzer
	XYZAnalyzer xyzAnalyzer(hostManager);
	// Add the new analyzer to the capture manager
	captureManager.addAnalyzer(&xyzAnalyzer);
	// Start capturing packets
	captureManager.startCapture();
}
```

By following these steps, you can add support for a new protocol to the NetProbe application.