#include "HostManager.hpp"
#include <boost/algorithm/string.hpp>
#include <ctime>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <mysql/mysql.h>
#include "Host.hpp"
#include <mutex>



std::mutex HostManager::mysqlMutex;
MYSQL* HostManager::mysql_conn = nullptr;

HostManager::HostManager() {
    std::lock_guard<std::mutex> lock(mysqlMutex);
    std::cout << "Initialisation de HostManager" << std::endl;
    // Récupération des variables d'environnement
    const char* db_host = std::getenv("DB_HOST");
    const char* db_user = std::getenv("DB_USER");
    const char* db_pass = std::getenv("DB_PASSWORD");
    const char* db_name = std::getenv("DB_NAME");
    const char* db_port_str = std::getenv("DB_PORT");
    unsigned int db_port = db_port_str ? std::stoi(db_port_str) : 3306;

    if (!db_host || !db_user || !db_pass || !db_name) {
        std::cerr << "Erreur: Variables d'environnement DB non définies" << std::endl;
        return;
    }


    std::string initDbSQL = "CREATE DATABASE IF NOT EXISTS " + std::string(db_name) + ";";
    MYSQL* init_conn = mysql_init(nullptr);
    if (mysql_real_connect(init_conn, db_host, db_user, db_pass, db_name, db_port, nullptr, 0)) {
        mysql_query(init_conn, initDbSQL.c_str());
        mysql_close(init_conn);
    }


    mysql_conn = mysql_init(nullptr);
    if (!mysql_conn) {
        std::cerr << "Erreur initialisation MySQL: " << mysql_error(mysql_conn) << std::endl;
        return;
    }

    if (!mysql_real_connect(mysql_conn, db_host, db_user, db_pass, db_name, db_port, nullptr, 0)) {
        std::cerr << "Erreur connexion MySQL: " << mysql_error(mysql_conn) << std::endl;
        mysql_close(mysql_conn);
        mysql_conn = nullptr;
        return;
    }

    // Création de la table si elle n'existe pas
    const char* createTableSQL = 
        "CREATE TABLE IF NOT EXISTS hosts ("
        "mac VARCHAR(17) PRIMARY KEY, "
        "ip VARCHAR(15), "
        "hostname TEXT, "
        "vendor TEXT, "
        "OS TEXT, "
        "first_seen BIGINT, "
        "last_seen BIGINT, "
        "protocole TEXT, "
        "data LONGTEXT) "
        "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

    if (mysql_query(mysql_conn, createTableSQL)) {
    std::cerr << "Erreur création table - Code: " << mysql_errno(mysql_conn)
              << " - Message: " << mysql_error(mysql_conn) << std::endl;
} else {
    std::cout << "Table 'hosts' créée avec succès ou déjà existante" << std::endl;
}
}

HostManager::~HostManager() {
    std::lock_guard<std::mutex> lock(mysqlMutex);
    if (mysql_conn) {
        mysql_close(mysql_conn);
        mysql_conn = nullptr;
    }
}


void HostManager::updateHost(ProtocolType protocol, std::unique_ptr<ProtocolData> data) {
    timespec first_seen, last_seen;

    auto processHost = [&](pcpp::MacAddress mac, pcpp::IPAddress ip, const std::string& hostname, ProtocolType type, const std::string& OS_Supposition = "") {
        updateHostSqlite(mac,ip,hostname,type,data, OS_Supposition );
    };

    switch (protocol) {
        case ProtocolType::ARP: {
            ARPData* arpData = dynamic_cast<ARPData*>(data.get());
            if (arpData) {
                processHost(arpData->senderMac, arpData->senderIp, "", ProtocolType::ARP);
            } 
            break;
        }
        case ProtocolType::DHCP: {
            DHCPData* dhcpData = dynamic_cast<DHCPData*>(data.get());
            if (dhcpData) {
                processHost(dhcpData->clientMac, dhcpData->ipAddress, dhcpData->hostname, ProtocolType::DHCP, dhcpData->fingerPrint);
            }
            break;
        }
        case ProtocolType::STP: {
            STPData* stpData = dynamic_cast<STPData*>(data.get());
            if (stpData) {
                processHost(stpData->senderMAC, pcpp::IPv4Address::Zero, "", ProtocolType::STP);
            }
            break;
        }
        case ProtocolType::LLDP: {
            LLDPData* lldpData = dynamic_cast<LLDPData*>(data.get());
            if (lldpData) {
                processHost(lldpData->senderMAC, pcpp::IPv4Address::Zero, lldpData->systemName, ProtocolType::LLDP);
            }
            break;
        }
        case ProtocolType::SSDP: {
            SSDPData* ssdpData = dynamic_cast<SSDPData*>(data.get());
            if (ssdpData) {
                processHost(ssdpData->senderMAC, ssdpData->senderIP, "", ProtocolType::SSDP);
            }
            break;
        }
        case ProtocolType::CDP: {
            CDPData* cdpData = dynamic_cast<CDPData*>(data.get());
            if (cdpData) {
                processHost(cdpData->senderMAC, cdpData->senderIP, "", ProtocolType::CDP);
            }
            break;
        }
        case ProtocolType::WOL: {
            WOLData* wolData = dynamic_cast<WOLData*>(data.get());
            if (wolData) {
                processHost(wolData->senderMAC, pcpp::IPv4Address::Zero, "", ProtocolType::WOL);
            }
            break;
        }
        case ProtocolType::ICMP: {
            ICMPData* icmpData = dynamic_cast<ICMPData*>(data.get());
            if (icmpData) {
                processHost(icmpData->senderMAC, icmpData->senderIP, "", ProtocolType::ICMP);
            }
            break;
        }
         case ProtocolType::MDNS: {
            mDNSData* mdnsData = dynamic_cast<mDNSData*>(data.get());
            if (mdnsData) {
                    processHost(mdnsData->clientMac, mdnsData->ipAddress, "", ProtocolType::MDNS);
            }
            break;
        }
        case ProtocolType::SNMP: {
            SNMPData* snmpData = dynamic_cast<SNMPData*>(data.get());
            if (snmpData) {
                if (!snmpData->oidName.empty() && snmpData->oidName.find("sysName") != std::string::npos && !snmpData->oidValue.empty()) {
                    processHost(snmpData->senderMAC, snmpData->senderIP, snmpData->oidValue, ProtocolType::SNMP);
                } else {
                    processHost(snmpData->senderMAC, snmpData->senderIP, "", ProtocolType::SNMP);
                }
            }
            break;
        }
        
        
    
    }
}

std::string protocolToString(ProtocolType type) {
    switch (type) {
        case ProtocolType::DHCP:
            return "DHCP";
        case ProtocolType::ARP:
            return "ARP";
        case ProtocolType::STP:
            return "STP";
        case ProtocolType::LLDP:
            return "LLDP";
        case ProtocolType::SSDP:
            return "SSDP";
        case ProtocolType::CDP:
            return "CDP";
        case ProtocolType::WOL:
            return "WOL";
        case ProtocolType::ICMP:
            return "ICMP";
        case ProtocolType::SNMP:
            return "SNMP";
        case ProtocolType::MDNS:
            return "mDNS";
        default:
            return "UNKNOWN";
    }
}

void HostManager::updateHostSqlite(pcpp::MacAddress mac, pcpp::IPAddress ip, const std::string& hostname,ProtocolType protocol, const std::unique_ptr<ProtocolData>& data, const std::string& OS_Supposition) {
    
    if (!mysql_conn) return;

    std::string macStr = mac.toString();
    std::string ipStr = ip.toString();
    std::string hostnameStr = hostname;
    std::string typeProtocole = protocolToString(protocol);
    std::string OS_suppositionStr = OS_Supposition;
    timespec now;  
    clock_gettime(CLOCK_REALTIME, &now);
    
    //data en json
    if (!data) {
        std::cerr << "[ERREUR] data est null dans updateHostSqlite\n";
        return;
    }

    Json::Value jsonData = data->toJson();
    //convertie en string 
    Json::StreamWriterBuilder writer;
    std::string jsonDataStr = Json::writeString(writer, jsonData);
    std::string vendor = getVendorName(macStr, vendorDatabase);

    // Récupération des données existantes
        std::string currentProtocols;
        std::string dataStr;
        std::string OSStr;
        std::string hostNameBdd;
        std::string ipBdd;

         {
        std::string query = "SELECT protocole, data, OS, hostname, ip FROM hosts WHERE mac = ?";
        MYSQL_STMT* stmt = mysql_stmt_init(mysql_conn);
        if (!stmt) {
            std::cerr << "Erreur préparation requête: " << mysql_error(mysql_conn) << std::endl;
            return;
        }

        if (mysql_stmt_prepare(stmt, query.c_str(), query.length())) {
            std::cerr << "Erreur préparation requête: " << mysql_stmt_error(stmt) << std::endl;
            mysql_stmt_close(stmt);
            return;
        }

        MYSQL_BIND param[1], result[5];
        memset(param, 0, sizeof(param));
        memset(result, 0, sizeof(result));

        // Paramètre mac
        param[0].buffer_type = MYSQL_TYPE_STRING;
        param[0].buffer = (char*)macStr.c_str();
        param[0].buffer_length = macStr.length();

        if (mysql_stmt_bind_param(stmt, param)) {
            std::cerr << "Erreur bind param: " << mysql_stmt_error(stmt) << std::endl;
            mysql_stmt_close(stmt);
            return;
        }

        // Résultats
        char protocole_buf[1024] = {0};
        char data_buf[65536] = {0};
        char os_buf[1024] = {0};
        char hostname_buf[1024] = {0};
        char ip_buf[64] = {0};

        result[0].buffer_type = MYSQL_TYPE_STRING;
        result[0].buffer = protocole_buf;
        result[0].buffer_length = sizeof(protocole_buf);

        result[1].buffer_type = MYSQL_TYPE_STRING;
        result[1].buffer = data_buf;
        result[1].buffer_length = sizeof(data_buf);

        result[2].buffer_type = MYSQL_TYPE_STRING;
        result[2].buffer = os_buf;
        result[2].buffer_length = sizeof(os_buf);

        result[3].buffer_type = MYSQL_TYPE_STRING;
        result[3].buffer = hostname_buf;
        result[3].buffer_length = sizeof(hostname_buf);

        result[4].buffer_type = MYSQL_TYPE_STRING;
        result[4].buffer = ip_buf;
        result[4].buffer_length = sizeof(ip_buf);

        if (mysql_stmt_bind_result(stmt, result)) {
            std::cerr << "Erreur bind result: " << mysql_stmt_error(stmt) << std::endl;
            mysql_stmt_close(stmt);
            return;
        }

        if (mysql_stmt_execute(stmt)) {
            std::cerr << "Erreur execution: " << mysql_stmt_error(stmt) << std::endl;
            mysql_stmt_close(stmt);
            return;
        }

        if (!mysql_stmt_fetch(stmt)) {
            currentProtocols = protocole_buf;
            dataStr = data_buf;
            OSStr = os_buf;
            hostNameBdd = hostname_buf;
            ipBdd = ip_buf;
        }

        mysql_stmt_close(stmt);
    }

    // Logique de fusion des données (identique à la version SQLite)
    if (!currentProtocols.empty()) {
        if (currentProtocols.find(typeProtocole) == std::string::npos) {
            currentProtocols += ", " + typeProtocole;
        }
    } else {
        currentProtocols = typeProtocole;
    }
     // On ajoute les nouvelles data
    if (!dataStr.empty()) {
        dataStr += jsonDataStr;
    } else {
        dataStr = jsonDataStr;
    }
        // On ajoute les nouvelles data
    if (!OSStr.empty()) {
       if(OS_suppositionStr.empty()){
            OSStr += OS_suppositionStr;
        } else {
           if (OSStr.size() < OS_suppositionStr.size()) {
            OSStr = OS_suppositionStr;
           } 
        }
    } else {
        OSStr = OS_suppositionStr;
    }

   
    if (hostnameStr.find("@") != std::string::npos || hostnameStr.find("._udp") != std::string::npos || hostnameStr.find("._tcp") != std::string::npos) {
        //on a un hostname qu'on n'aime pas 
        if(!hostNameBdd.empty()){
            //et si on a un hostname dans la bdd on le prend
             hostnameStr = hostNameBdd;
        } 
    }else{
        //sinon si notre hostname nous conviens ou est vide
        if(!hostNameBdd.empty()){
            //que il y a déjà un hostname dans la BDD
                if(hostnameStr.empty()){
                    //si hsotname vide alors on prend celui de la bdd 
                    hostnameStr = hostNameBdd;
                } else {
                    if (hostnameStr.size() < hostNameBdd.size()) {
                        hostnameStr = hostNameBdd;
                    }
                }
            }
    }
    
    //si notre IP est  0.0.0.0 on met l'IP de la bdd
    if(ipStr == "0.0.0.0"){
        if(!ipBdd.empty()){
            ipStr = ipBdd;
        }
    }


    // Requête d'insertion/mise à jour
    std::string sql = 
        "INSERT INTO hosts (mac, ip, hostname, vendor, OS, first_seen, last_seen, protocole, data) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON DUPLICATE KEY UPDATE "
        "ip = VALUES(ip), "
        "hostname = VALUES(hostname), "
        "last_seen = VALUES(last_seen), "
        "OS = VALUES(OS), "
        "protocole = VALUES(protocole), "
        "data = VALUES(data);";

    MYSQL_STMT* stmt = mysql_stmt_init(mysql_conn);
    if (!stmt) {
        std::cerr << "Erreur préparation requête: " << mysql_error(mysql_conn) << std::endl;
        return;
    }

    if (mysql_stmt_prepare(stmt, sql.c_str(), sql.length())) {
        std::cerr << "Erreur préparation requête: " << mysql_stmt_error(stmt) << std::endl;
        mysql_stmt_close(stmt);
        return;
    }

    MYSQL_BIND bind[9];
    memset(bind, 0, sizeof(bind));

    // mac
    bind[0].buffer_type = MYSQL_TYPE_STRING;
    bind[0].buffer = (char*)macStr.c_str();
    bind[0].buffer_length = macStr.length();

    // ip
    bind[1].buffer_type = MYSQL_TYPE_STRING;
    bind[1].buffer = (char*)ipStr.c_str();
    bind[1].buffer_length = ipStr.length();

    // hostname
    bind[2].buffer_type = MYSQL_TYPE_STRING;
    bind[2].buffer = (char*)hostnameStr.c_str();
    bind[2].buffer_length = hostnameStr.length();

    // vendor
    bind[3].buffer_type = MYSQL_TYPE_STRING;
    bind[3].buffer = (char*)vendor.c_str();
    bind[3].buffer_length = vendor.length();

    // OS
    bind[4].buffer_type = MYSQL_TYPE_STRING;
    bind[4].buffer = (char*)OSStr.c_str();
    bind[4].buffer_length = OSStr.length();

    // first_seen
    bind[5].buffer_type = MYSQL_TYPE_LONGLONG;
    bind[5].buffer = &now.tv_sec;
    bind[5].is_unsigned = true;

    // last_seen
    bind[6].buffer_type = MYSQL_TYPE_LONGLONG;
    bind[6].buffer = &now.tv_sec;
    bind[6].is_unsigned = true;

    // protocole
    bind[7].buffer_type = MYSQL_TYPE_STRING;
    bind[7].buffer = (char*)currentProtocols.c_str();
    bind[7].buffer_length = currentProtocols.length();

    // data
    bind[8].buffer_type = MYSQL_TYPE_STRING;
    bind[8].buffer = (char*)dataStr.c_str();
    bind[8].buffer_length = dataStr.length();

    if (mysql_stmt_bind_param(stmt, bind)) {
        std::cerr << "Erreur bind param: " << mysql_stmt_error(stmt) << std::endl;
        mysql_stmt_close(stmt);
        return;
    }

    if (mysql_stmt_execute(stmt)) {
        std::cerr << "Erreur execution: " << mysql_stmt_error(stmt) << std::endl;
    }

    mysql_stmt_close(stmt);


}