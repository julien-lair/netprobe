#include "DHCPAnalyzer.hpp"

// Helper function to extract option data as a string (IP address or text)
pcpp::IPAddress getDhcpOption(pcpp::DhcpLayer* dhcpLayer, pcpp::DhcpOptionTypes optionType, const std::string& defaultValue = "Not Assigned") {
    pcpp::DhcpOption option = dhcpLayer->getOptionData(optionType);
    if (!option.isNull()) {
        if (option.getType() == pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS || 
            option.getType() == pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER ||
            option.getType() == pcpp::DhcpOptionTypes::DHCPOPT_ROUTERS ||
            option.getType() == pcpp::DhcpOptionTypes::DHCPOPT_DOMAIN_NAME_SERVERS) {
            return option.getValueAsIpAddr();
        }
    }
    return pcpp::IPv4Address::Zero;
}

std::string getDhcpMessageType(uint8_t type, const uint8_t* data, size_t length) {
    if (length == 1 && type == 53) { // DHCP Message Type{
        const std::map<uint8_t, std::string> messageTypes = {
            {1, "DISCOVER"}, {2, "OFFER"}, {3, "REQUEST"},
            {4, "DECLINE"}, {5, "ACK"}, {6, "NAK"}, {7, "RELEASE"}
        };
        auto it = messageTypes.find(data[0]);
        if (it != messageTypes.end()) {
            return it->second + " (" + std::to_string(static_cast<int>(data[0])) + ")";
        } else {
            return "Unknown (" + std::to_string(static_cast<int>(data[0])) + ")";
        }
    }
}

std::string getDhcpFingerPrint(uint8_t type, const uint8_t* data, size_t length) {
    if (type == 55) { // DHCP Parameter Request List
        std::string fingerPrint;
        for (size_t i = 0; i < length; ++i) {
            if (i > 0) fingerPrint += ",";
            fingerPrint += std::to_string(static_cast<int>(data[i]));
        }

        std::string command = "python3 Scripts/dhcp_fingerprint.py " + fingerPrint;

        std::array<char, 128> buffer;
        std::string result;
        std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);

        if (!pipe) {
            throw std::runtime_error("popen() failed!");
        }

        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            result += buffer.data();
        }

        return result;
    } else {
        return "";
    }
}


std::string getDhcpHostname(uint8_t type, const uint8_t* data, size_t length) {
    if (type == 12) { // Hostname
        return std::string(reinterpret_cast<const char*>(data), length);
    } else {
        return "";
    }
}

void DHCPAnalyzer::analyzePacket(pcpp::Packet& parsedPacket) {

    auto* dhcpLayer = parsedPacket.getLayerOfType<pcpp::DhcpLayer>();

    if (!dhcpLayer) {
        return; // Not an Ethernet, IPv4, UDP, or DHCP packet
    }

    // Extract DHCP information using helper function
    pcpp::MacAddress clientMac = dhcpLayer->getClientHardwareAddress();
    pcpp::IPAddress ipAddress =  getDhcpOption(dhcpLayer, pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS);
    pcpp::IPAddress dhcpServerIp = getDhcpOption(dhcpLayer, pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER);
    pcpp::IPAddress gatewayIp = getDhcpOption(dhcpLayer, pcpp::DHCPOPT_ROUTERS);
    pcpp::IPAddress dnsServerIp = getDhcpOption(dhcpLayer, pcpp::DHCPOPT_DOMAIN_NAME_SERVERS);
    std::string hostname = "";
    std::string fingerPrint = "";
    std::string messageType = "";


    for (auto opt = dhcpLayer->getFirstOptionData(); opt.isNotNull(); opt = dhcpLayer->getNextOptionData(opt)) {
        uint8_t type = opt.getType();
        if (opt.getDataSize() > 0 && opt.getValue() != nullptr) {
            uint8_t* data = opt.getValue();
            if(type == 53) { // DHCP Message Type
                messageType = getDhcpMessageType(type, data, opt.getDataSize());
            } else if (type == 55) { // Parameter Request List
                fingerPrint = getDhcpFingerPrint(type, data, opt.getDataSize());
            } else if (type == 12) { // Hostname
                hostname = getDhcpHostname(type, data, opt.getDataSize());
            }
        }
    }




    pcpp::RawPacket* rawPacket = parsedPacket.getRawPacket();
    timespec ts = rawPacket->getPacketTimeStamp();

    // Update the host manager with the DHCP data
    // Check if MAC and IP are valid
    if (clientMac == pcpp::MacAddress::Zero || ipAddress.isZero()) {
        return; // Invalid MAC or IP, exit the function
    }
    
    auto dhcpData = std::make_unique<DHCPData>(ts, clientMac, ipAddress, hostname, dhcpServerIp, gatewayIp, dnsServerIp, fingerPrint, messageType);
    
    #ifdef DEBUG
    std::cout << "DHCP Packet:" << std::endl;
    std::cout << "\tClient MAC: " << clientMac << std::endl;
    std::cout << "\tIP Address: " << ipAddress << std::endl;
    std::cout << "\tDHCP Server IP: " << dhcpServerIp << std::endl;
    std::cout << "\tGateway IP: " << gatewayIp << std::endl;
    std::cout << "\tDNS Server IP: " << dnsServerIp << std::endl;
    std::cout << "\tHostname: " << hostname << std::endl;
    std::cout << "\tFingerPrint: " << fingerPrint << std::endl;
    std::cout << "\tMessage Type: " << messageType << std::endl;
    #endif
    
    hostManager.updateHost(ProtocolType::DHCP, std::move(dhcpData));
}
