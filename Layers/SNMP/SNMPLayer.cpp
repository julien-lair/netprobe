#include "SNMPLayer.hpp"
#include <sstream>
#include <cstring>
#include <cstdio>
#include <iostream>

SNMPLayer::SNMPLayer(const uint8_t* data, size_t dataLen)
    : rawData(data)
    , rawDataLength(dataLen)
    , version(SNMPLayer::SNMP_V2C)
    , communityName("")
    , type(SNMPLayer::GET_REQUEST)
    , errorStatus(SNMPLayer::NO_ERROR)
    , requestId(0)
{
    if (dataLen < 2) {
        throw std::invalid_argument("Packet too short for SNMP");
    }
    parseSNMP();
}

SNMPLayer::~SNMPLayer() {}

size_t readLength(const uint8_t* data, size_t& offset) {
    uint8_t first = data[offset++];
    if ((first & 0x80) == 0) {
        // Short form (length in first byte)
        return first;
    } else {
        // Long form
        int numBytes = first & 0x7F;
        size_t len = 0;
        for (int i = 0; i < numBytes; ++i) {
            len = (len << 8) | data[offset++];
        }
        return len;
    }
}


void SNMPLayer::parseSNMP() {
    size_t offset = 0;
    // 1) MESSAGE SEQUENCE
    if (rawData[offset++] != 0x30) 
        throw std::runtime_error("Invalid SNMP: no SEQUENCE");
    uint8_t len = rawData[offset++];
    if (len & 0x80) offset += (len & 0x7F);

    // 2) VERSION
    if (rawData[offset++] != 0x02) 
        throw std::runtime_error("Invalid SNMP: no version tag");
    uint8_t vlen = rawData[offset++];
    int ver = rawData[offset];
    offset += vlen;
    version = (ver == 0 ? SNMP_V1 : ver == 3 ? SNMP_V3 : SNMP_V2C);

    // 3) COMMUNITY (v1/v2c) or SECURITY PARAMETERS (v3 — not parsed)
    if (rawData[offset++] != 0x04) 
        throw std::runtime_error("Invalid SNMP: no community string tag");
    uint8_t clen = rawData[offset++];
    communityName.assign(reinterpret_cast<const char*>(rawData + offset), clen);
    offset += clen;

    // 4) PDU TYPE
    uint8_t pduTag = rawData[offset++];
    type = static_cast<SNMPLayer::SNMPType>(pduTag);

    // 5) SKIP PDU LENGTH
    uint8_t pduLen = rawData[offset++];
    if (pduLen & 0x80) offset += (pduLen & 0x7F);

    // --- Special case: SNMPv1 TRAP (0xA4) ---
    if (pduTag == SNMPLayer::TRAP_V1) {
        // enterprise OID
        if (rawData[offset++] != 0x06) throw std::runtime_error("Invalid SNMPv1 Trap: no enterprise OID");
        uint8_t eoLen = rawData[offset++];
        offset += eoLen;

        // agent address (NetworkAddress, tag 0x40)
        if (rawData[offset++] != 0x40) throw std::runtime_error("Invalid SNMPv1 Trap: no agent address");
        uint8_t aaLen = rawData[offset++];
        offset += aaLen;

        // generic trap (INTEGER)
        if (rawData[offset++] != 0x02) throw std::runtime_error("Invalid SNMPv1 Trap: no generic-trap");
        uint8_t gtLen = rawData[offset++];
        offset += gtLen;

        // specific trap (INTEGER)
        if (rawData[offset++] != 0x02) throw std::runtime_error("Invalid SNMPv1 Trap: no specific-trap");
        uint8_t stLen = rawData[offset++];
        offset += stLen;

        // timestamp (TIMETICKS, tag 0x43)
        if (rawData[offset++] != 0x43) throw std::runtime_error("Invalid SNMPv1 Trap: no time-stamp");
        uint8_t tsLen = rawData[offset++];
        offset += tsLen;
        // now fall through to varbinds
    } 
    else {
        // STANDARD PDU (contains request-id, error-status, error-index)
        // 6) REQUEST-ID
        if (rawData[offset++] != 0x02) 
            throw std::runtime_error("Invalid SNMP PDU: no request-id tag");
        uint8_t idlen = rawData[offset++];
        requestId = 0;
        for (int i = 0; i < idlen; ++i) {
            requestId = (requestId << 8) | rawData[offset++];
        }

        // 7) ERROR-STATUS
        if (rawData[offset++] != 0x02) 
            throw std::runtime_error("Invalid SNMP PDU: no error-status tag");
        uint8_t stlen = rawData[offset++];
        errorStatus = static_cast<SNMPLayer::SNMPErrorStatus>(rawData[offset]);
        offset += stlen;

        // 8) ERROR-INDEX
        if (rawData[offset++] != 0x02) 
            throw std::runtime_error("Invalid SNMP PDU: no error-index tag");
        uint8_t idxlen = rawData[offset++];
        offset += idxlen;
    }

    // 9) VARIABLE BINDINGS (SEQUENCE of VarBind)
    if (rawData[offset++] != 0x30) 
        throw std::runtime_error("Invalid SNMP PDU: no varbind sequence");
    uint8_t vbLen = rawData[offset++];
    if (vbLen & 0x80) offset += (vbLen & 0x7F);

    size_t vbEnd = offset + vbLen;
    while (offset < vbEnd) {
        if (rawData[offset++] != 0x30) break;
        uint8_t seqLen = rawData[offset++];
        size_t seqEnd = offset + seqLen;

        // OID
        if (rawData[offset++] != 0x06) break;
        //uint8_t oidLen = rawData[offset++];
        size_t oidLen = readLength(rawData, offset);
        //afficher la longeur en hexa et en entier 
        std::cout << "OID Length: " << std::hex << oidLen << std::dec << std::endl;

        std::ostringstream oid;
        for (int i = 0; i < oidLen; ++i) {
            oid << int(rawData[offset++]);
            if (i < oidLen - 1) oid << '.';
        }
        
        // Value
        std::string val;
        uint8_t valTag = rawData[offset++];
        uint8_t vlen2  = rawData[offset++];
        if (valTag == 0x04) { 
            val.assign(reinterpret_cast<const char*>(rawData + offset), vlen2);
        }
        else if (valTag == 0x02) {
            long ival = 0;
            for (int i = 0; i < vlen2; ++i) ival = (ival << 8) | rawData[offset + i];
            val = std::to_string(ival);
        }
        offset += vlen2;

        // Resolve name
        if (oid.str().find("4") == 0) {
            std::string newOid = "1." + oid.str().substr(1);
            oid.str(newOid);
           
        }

        std::string oidStr = oid.str();
        //at the and of the oid str add "!! oidLen" 
        //oidStr += "!!" + std::to_string(oidLen);
        auto it = oidCache.find(oidStr);
        std::string name = (it != oidCache.end()) ? it->second : resolveOid(oidStr);
        oidCache[oidStr] = name;

        oids.push_back({ oidStr, name, val });
        offset = seqEnd;
    }
}

SNMPLayer::SNMPVersion SNMPLayer::getVersion() const {
    return version;
}

const std::string& SNMPLayer::getCommunityName() const {
    return communityName;
}

SNMPLayer::SNMPType SNMPLayer::getType() const {
    return type;
}

SNMPLayer::SNMPErrorStatus SNMPLayer::getErrorStatus() const {
    return errorStatus;
}

int SNMPLayer::getRequestId() const {
    return requestId;
}

const std::vector<SNMPLayer::OIDEntry>& SNMPLayer::getOIDs() const {
    return oids;
}

std::ostream& operator<<(std::ostream& os, const SNMPLayer& snmp) {
    os << "SNMP Layer:\n";
    os << "  Version: "      << snmp.getVersion()      << "\n";
    os << "  Community: "    << snmp.getCommunityName() << "\n";
    os << "  PDU Type: 0x"   << std::hex << snmp.getType() << std::dec << "\n";
    if (snmp.getType() != SNMPLayer::TRAP_V1) {
        os << "  Request ID: "   << snmp.getRequestId() << "\n";
        os << "  Error Status: " << int(snmp.getErrorStatus()) << "\n";
    } else {
        os << "  Trap SNMPv1 (no request-id)\n";
    }
    os << "  OIDs:\n";
    for (auto& e : snmp.getOIDs())
        os << "    " << e.mibName << " (" << e.oid << "): " << e.value << "\n";
    return os;
}
