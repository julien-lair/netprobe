#ifndef SNMPLAYER_HPP
#define SNMPLAYER_HPP

#include <string>
#include <vector>
#include <unordered_map>
#include <stdexcept>
#include <memory>
#include <array>
#include <cstdio>

/**
 * @class SNMPLayer
 * 
 * @brief Represents an SNMP layer in a network packet.
 * 
 * The SNMPLayer class provides methods for accessing and parsing SNMP data from a network packet.
 * It extracts information such as the SNMP version, community string, PDU type, error status, and requested OIDs.
 * The class also supports mapping OIDs to their MIB names using an external resolution function
 * (e.g., via snmptranslate) or a local cache.
 * 
 * Typical OIDs include:
 *  - 1.3.6.1.2.1.1.1.0 → sysDescr
 *  - 1.3.6.1.2.1.1.5.0 → sysName
 *  - 1.3.6.1.2.1.1.3.0 → sysUpTime
 *  - 1.3.6.1.2.1.2.2.1.2.X → ifDescr
 * 
 * You can get OID descriptions using: `snmptranslate -On -Td <OID>`
 */
class SNMPLayer {
public:
    // Constructor and Destructor
    SNMPLayer(const uint8_t* data, size_t dataLen);
    ~SNMPLayer();

    // SNMP enums
    enum SNMPVersion {
        SNMP_V1 = 0,
        SNMP_V2C = 1,
        SNMP_V3 = 3
    };

    enum SNMPType {
        GET_REQUEST       = 0xA0,
        GET_NEXT_REQUEST  = 0xA1,
        GET_RESPONSE      = 0xA2,
        SET_REQUEST       = 0xA3,
        TRAP_V1           = 0xA4,
        BULK_REQUEST      = 0xA5,
        INFORM_REQUEST    = 0xA6,
        TRAP_V2           = 0xA7,
        REPORT            = 0xA8
    };

    enum SNMPErrorStatus {
        NO_ERROR = 0,
        TOO_BIG,
        NO_SUCH_NAME,
        BAD_VALUE,
        READ_ONLY,
        GENERIC_ERROR,
        NO_ACCESS,
        WRONG_TYPE,
        WRONG_LENGTH,
        WRONG_ENCODING,
        WRONG_VALUE,
        NO_CREATION,
        INCONSISTENT_VALUE,
        RESOURCE_UNAVAILABLE,
        COMMIT_FAILED,
        UNDO_FAILED,
        AUTHORIZATION_ERROR
    };

    struct OIDEntry {
        std::string oid;       ///< Raw OID (e.g. "1.3.6.1.2.1.1.1.0")
        std::string mibName;   ///< MIB name (e.g. "IF-MIB::sysDescr")
        std::string value;     ///< Value associated with this OID
    };

    // Public getters
    SNMPVersion            getVersion() const;
    const std::string&     getCommunityName() const;
    SNMPType getType() const;
    SNMPErrorStatus        getErrorStatus() const;
    int                    getRequestId() const;
    const std::vector<OIDEntry>& getOIDs() const;

    /**
     * @brief Resolves an OID string to its MIB name using snmptranslate.
     *
     * @param oid The numeric OID (e.g. "1.3.6.1.2.1.1.1.0").
     * @return The MIB name (e.g. "IF-MIB::sysDescr"), or the input OID on failure.
     */
    static std::string resolveOid(const std::string& oid) {
        std::array<char, 128> buffer;
        std::string result;
        std::string cmd = "snmptranslate -On -Td " + oid + " 2>/dev/null";
        std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
        if (!pipe) throw std::runtime_error("Failed to run snmptranslate");
        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            result += buffer.data();
        }
        // Extract the MIB::name line
        auto pos = result.find("::");
        if (pos != std::string::npos) {
            auto start = result.rfind('\n', pos);
            start = (start == std::string::npos ? 0 : start + 1);
            auto end = result.find('\n', pos);
            return result.substr(start, end - start);
        }
        return oid;  // fallback
    }

private:
    // Raw packet data
    const uint8_t*        rawData;
    size_t                rawDataLength;

    // Parsed SNMP fields
    SNMPVersion           version;
    std::string           communityName;
    SNMPType              type;
    SNMPErrorStatus       errorStatus;
    int                   requestId;
    std::vector<OIDEntry> oids;

    // Internal parser
    void parseSNMP();

    // Cache for resolved OIDs
    std::unordered_map<std::string, std::string> oidCache;
};

#endif // SNMPLAYER_HPP
