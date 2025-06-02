#ifndef SSDP_LAYER_HPP
#define SSDP_LAYER_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <ostream>

    class SSDPLayer {
    public:
        enum SSDPType {
            NOTIFY,
            MSEARCH
        };
        SSDPLayer(const uint8_t* data, size_t length);
        SSDPType getSSDPType() const;
        std::vector<std::pair<std::string, std::string>> getSSDPHeaders() const;
        friend std::ostream& operator<<(std::ostream& os, const SSDPLayer& layer);
        
    private:
        const uint8_t* rawData;
        size_t rawDataLength;

        SSDPType ssdpType;
        // Contains all the SSDP headers
        std::vector<std::pair<std::string, std::string>> ssdpHeaders;

        void parseSSDPDU();
    };


#endif // SSDP_LAYER_HPP