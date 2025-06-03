#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>
#include <atomic>
#include "CaptureManager.hpp"
#include "Analyzers/DHCP/DHCPAnalyzer.hpp"
#include "Analyzers/mDNS/mDNSAnalyzer.hpp"
#include "Analyzers/ARP/ARPAnalyzer.hpp"
#include "Analyzers/STP/STPAnalyzer.hpp"
#include "Analyzers/SSDP/SSDPAnalyzer.hpp"
#include "Analyzers/CDP/CDPAnalyzer.hpp"
#include "Analyzers/LLDP/LLDPAnalyzer.hpp"
#include "Analyzers/WOL/WOLAnalyzer.hpp"
#include "Analyzers/ICMP/ICMPAnalyzer.hpp"
#include "Analyzers/SNMP/SNMPAnalyzer.hpp"
#include "Hosts/HostManager.hpp"
#include <atomic>

void rearm_sigusr1(boost::asio::signal_set& signals, std::atomic<bool>& dumpHosts) {
    // Asynchronously wait for SIGUSR1 signal
    signals.async_wait([&signals, &dumpHosts](const boost::system::error_code& error, int signum) {
        if (!error && signum == SIGUSR1) {
            std::cout << "Signal (" << signum << ") received, dumping hosts file..." << std::endl;
            dumpHosts = true;

            // Rearm the handler for future signals
            rearm_sigusr1(signals, dumpHosts);
        } else if (error) {
            std::cerr << "Error handling signal: " << error.message() << std::endl;
        }
    });
}

int main() {
    loadVendorDatabase("/netprobe/build/manuf", vendorDatabase); // si programme lancée depuis le dossier build : ../../Hosts/manuf
    //si programme lancée depuis le docker : /netprobe/build/manuf

    // Get the network interface from environment variable
    const char* interfaceEnv = getenv("INTERFACE");
    if (!interfaceEnv) {
        std::cerr << "Error: INTERFACE environment variable is not set." << std::endl;
        return 1;
    }
    std::string interface = interfaceEnv;


    std::atomic<bool> running(true); // Atomic flag for the infinite loop
    // Atomic flag for the infinite loop to dump hosts
    std::atomic<bool> dumpHosts(false);
    // Get the timeout duration from environment variable
    const char* durationEnv = getenv("TIMEOUT");
    if (!durationEnv) {
        std::cerr << "Error: TIMEOUT environment variable is not set." << std::endl;
        return 1;
    }
    std::string durationStr = durationEnv;
    bool isInfinite = (durationStr == "-1");

    // Convert duration to integer if not infinite
    int duration = isInfinite ? 0 : std::stoi(durationStr);
    int timer = 0;
    boost::asio::io_context io_context;
    boost::asio::signal_set signals(io_context, SIGUSR1, SIGINT, SIGTERM);

    // Stop the infinite loop when a signal (e.g., SIGINT) is received
    signals.async_wait([&running](const boost::system::error_code& error, int signum) {
        if (!error && signum == SIGINT) {
            std::cout << "Signal (" << signum << ") received, stopping packet capture..." << std::endl;
            running = false; // Break the loop
        }
    });

    // Rearm the handler for SIGUSR1 signal
    rearm_sigusr1(signals, dumpHosts);

    // Create the host manager
    HostManager hostManager;

    // Start the IO context in a separate thread
    std::thread io_thread([&io_context]() { io_context.run(); });

    // Create the capture manager
    CaptureManager captureManager(interface);

    // Create analyzers
    DHCPAnalyzer dhcpAnalyzer(hostManager);
    mDNSAnalyzer mdnsAnalyzer(hostManager);
    ARPAnalyzer arpAnalyzer(hostManager);
    STPAnalyzer stpAnalyzer(hostManager);
    SSDPAnalyzer ssdpAnalyzer(hostManager);
    CDPAnalyzer cdpAnalyzer(hostManager);
    LLDPAnalyzer lldpAnalyzer(hostManager);
    WOLAnalyzer wolAnalyzer(hostManager);
    ICMPAnalyzer icmpAnalyzer(hostManager);
    SNMPAnalyzer snmpAnalyzer(hostManager);

    // Add analyzers to the manager
    captureManager.addAnalyzer(&dhcpAnalyzer);
    captureManager.addAnalyzer(&mdnsAnalyzer);
    captureManager.addAnalyzer(&arpAnalyzer);
    captureManager.addAnalyzer(&stpAnalyzer);
    captureManager.addAnalyzer(&ssdpAnalyzer);
    captureManager.addAnalyzer(&cdpAnalyzer);
    captureManager.addAnalyzer(&lldpAnalyzer);
    captureManager.addAnalyzer(&wolAnalyzer);
    captureManager.addAnalyzer(&icmpAnalyzer);
    captureManager.addAnalyzer(&snmpAnalyzer);
    // Start capturing packets
    std::cout << "Starting packet capture on interface: " << interface << std::endl;

    try {
        captureManager.startCapture();

        if (isInfinite) {
            std::cout << "Capturing packets indefinitely. Press Ctrl+C to stop." << std::endl;

            // Infinite loop controlled by the atomic flag
            while (running) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        } else {
            std::cout << "Capturing packets for " << duration << " seconds" << std::endl;

            // Finite loop for the given duration
            for (int i = 0; i < duration; i++) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception occurred during capture: " << e.what() << std::endl;
    }

    // Attempt to stop the capture gracefully
    try {
        captureManager.stopCapture();
        std::cout << "Packet capture stopped." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Exception occurred while stopping capture: " << e.what() << std::endl;
    }


    std::cout << "Program terminated." << std::endl;

    io_thread.join();
    return 0;
}

