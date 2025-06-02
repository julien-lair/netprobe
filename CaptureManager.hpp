#include "Analyzers/Analyzer.hpp"

// CaptureManager class
/**
 * @class CaptureManager
 * @brief Manages packet capture and distribution to analyzers.
 * 
 * The CaptureManager class is responsible for managing packet capture on a network interface
 * and distributing captured packets to a list of analyzers. It provides methods to start and
 * stop packet capture, add analyzers to the list, and handle packet distribution to the analyzers.
 */
class CaptureManager {
private:
    pcpp::PcapLiveDevice *device;
    std::vector<Analyzer*> analyzers;

public:
    CaptureManager(const std::string &interface) {
        // Find the network interface by IP address
        device = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interface);
        if (device == NULL) {
            std::cerr << "Error: Unable to find the device with IP: " << interface << std::endl;
            exit(1);
        }
    }

    // Destructor
    ~CaptureManager() {
    }

    // Add an analyzer to the list
    void addAnalyzer(Analyzer* analyzer) {
        analyzers.push_back(analyzer);
    }

    // Start capturing packets
    void startCapture() {
        if (!device->open()) {
            std::cerr << "Error: Unable to open the device for capturing" << std::endl;
            exit(1);
        }

        std::cout << "Starting packet capture on interface: " << device->getName() << std::endl;

        // Start capturing, providing a callback function
        device->startCapture(onPacketArrives, this);
    }

    // Stop capturing packets
    void stopCapture() {
        device->stopCapture();
        device->close();
    }

    // Static callback for packet arrival
    static void onPacketArrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *dev, void *cookie) {
        CaptureManager *manager = (CaptureManager *)cookie;
        manager->handlePacket(packet);
    }

    // Handle and distribute packet to all analyzers
    void handlePacket(pcpp::RawPacket *rawPacket) {
        // Parse the raw packet
        pcpp::Packet parsedPacket(rawPacket);

        // Distribute packet to all analyzers
        for (Analyzer* analyzer : analyzers) {
            analyzer->analyzePacket(parsedPacket);
        }
    }
};