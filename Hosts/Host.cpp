#include "Host.hpp"

std::map<std::string, std::string> vendorDatabase;

void Host::getProtocolData(ProtocolType protocol, ProtocolData& data) const {
    auto& protocolSet = protocols_data[static_cast<size_t>(protocol)];
    auto it = protocolSet.find(std::make_unique<ProtocolData>(protocol));

    if (it != protocolSet.end()) {
        data = **it;
    }
}

void Host::updateProtocolData(ProtocolType protocol, std::unique_ptr<ProtocolData> data) {
    auto& protocolSet = protocols_data[static_cast<size_t>(protocol)];
    auto it = protocolSet.find(data);

    // Check if the entry already exists
    if (it != protocolSet.end()) {
        // Update the timestamp if the entry already exists
        (*it)->timestamp = data->timestamp;
        
    } else {
        // Insert the new entry
        protocolSet.insert(std::move(data));
    }
}

void Host::editProtocolData(ProtocolType protocol, std::unique_ptr<ProtocolData> prev_data, std::unique_ptr<ProtocolData> new_data) {
    auto& protocolSet = protocols_data[static_cast<size_t>(protocol)];
    auto it = protocolSet.find(prev_data);

    if (it != protocolSet.end()) {
        // Update the timestamp if the entry already exists
        (*it)->timestamp = new_data->timestamp;
        protocolSet.insert(std::move(new_data));
        protocolSet.erase(it);
    } else {
        // Insert the new entry
        protocolSet.insert(std::move(new_data));
    }
}

// Function to load vendor information from a file into the map
/**
 * @file Host.cpp
 * @brief Implementation of functions related to loading vendor database.
 */

/**
 * @brief Loads a vendor database from a file into a map.
 *
 * This function reads a file containing MAC address prefixes and their corresponding vendor names,
 * and populates the provided map with this data. Each line in the file should contain a MAC address
 * prefix followed by the vendor name.
 *
 * @param filename The path to the file containing the vendor database.
 * @param vendorDatabase A reference to a map where the MAC address prefixes and vendor names will be stored.
 */
void loadVendorDatabase(const std::string& filename, std::map<std::string, std::string>& vendorDatabase) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error opening file!" << std::endl;
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        // Skip empty lines or lines that don't have at least two columns
        if (line.empty()) {
            continue;
        }

        std::stringstream ss(line);
        std::string macPrefix, vendorName;
        
        // Read the MAC prefix (first part) and vendor name (second part)
        ss >> macPrefix; // The MAC address prefix
        std::getline(ss, vendorName); // The rest of the line is the vendor name
        
        // Trim leading spaces from vendor name
        size_t start = vendorName.find_first_not_of(" \t");
        vendorName = vendorName.substr(start);

        // Insert the macPrefix and vendorName into the map
        vendorDatabase[macPrefix] = vendorName;
    }

    file.close();
}

// Function to swap the first and second byte of the MAC address
void swapMacBytes(std::string& mac) {
    std::string firstByte = mac.substr(0, 2);
    std::string secondByte = mac.substr(3, 2);
    
    // Swap the first and second byte
    mac = secondByte + ":" + firstByte + mac.substr(5);
}

// Function to get vendor name from MAC prefix
std::string getVendorName(const std::string& mac, const std::map<std::string, std::string>& vendorDatabase) {
    std::string macPrefix = mac;
    std::transform(macPrefix.begin(), macPrefix.end(), macPrefix.begin(), ::toupper);
    macPrefix = macPrefix.substr(0, 8);  // Get the first 3 bytes of the MAC address
    // Check if the MAC prefix is in the vendor database
    auto it = vendorDatabase.find(macPrefix);
    if (it != vendorDatabase.end()) {
        return it->second;
    }
    return "Unknown Vendor";  // Default if the vendor is not found
}

std::string pcppMACAddressToString(const pcpp::MacAddress& mac, const std::map<std::string, std::string>& vendorDatabase) {
    std::string macStr = mac.toString();
    std::cout << "MAC: " << macStr << std::endl;
    std::transform(macStr.begin(), macStr.end(), macStr.begin(), ::toupper);
    std::string vendorName = getVendorName(macStr.substr(0, 8), vendorDatabase);
    std::cout << "sub: " << macStr.substr(0, 8) << std::endl;
    return macStr ;//+ " (" + vendorName + ")";
}