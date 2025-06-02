cmake_minimum_required(VERSION 3.5.0)
project(netprobe VERSION 0.1.0 LANGUAGES C CXX)

# Trouver les dépendances
find_package(PkgConfig REQUIRED)
find_package(Boost REQUIRED)

# Configurer MySQL différemment
find_path(MYSQL_INCLUDE_DIR mysql.h
    PATHS
    /usr/include/mysql
    /usr/local/include/mysql
    /usr/include/mariadb
    /usr/local/include/mariadb
)

find_library(MYSQL_LIBRARIES NAMES mysqlclient mariadb
    PATHS
    /usr/lib
    /usr/local/lib
    /usr/lib/mysql
    /usr/lib64/mysql
)

if(MYSQL_INCLUDE_DIR AND MYSQL_LIBRARIES)
    message(STATUS "Found MySQL: includes at ${MYSQL_INCLUDE_DIR}, libraries at ${MYSQL_LIBRARIES}")
else()
    message(FATAL_ERROR "MySQL not found")
endif()

# Configurer PcapPlusPlus et autres dépendances
include(FindPCAP.cmake)
find_package(PcapPlusPlus REQUIRED)
pkg_check_modules(JSONCPP jsoncpp)

# Collect source files
file(GLOB_RECURSE sources
    "main.cpp"
    "Analyzers/DHCP/*.cpp"
    "Analyzers/mDNS/*.cpp"
    "Analyzers/ARP/*.cpp"
    "Analyzers/SSDP/*.cpp"
    "Analyzers/LLDP/*.cpp"
    "Analyzers/STP/*.cpp"
    "Analyzers/CDP/*.cpp"
    "Analyzers/WOL/*.cpp"
    "Analyzers/SNMP/*.cpp"
    "Analyzers/ICMP/*.cpp"
    "Layers/LLDP/*.cpp"
    "Layers/STP/*.cpp"
    "Layers/SSDP/*.cpp"
    "Layers/CDP/*.cpp"
    "Layers/SNMP/*.cpp"
    "Hosts/*.cpp"
)

# Exécutable
add_executable(netprobe ${sources})

# Liaisons
target_include_directories(netprobe PRIVATE
    ${PCAP_INCLUDE_DIR}
    ${JSONCPP_INCLUDE_DIRS}
    ${PcapPlusPlus_INCLUDE_DIRS}
    ${MYSQL_INCLUDE_DIR}
    "/usr/local/include/pcapplusplus"
)

target_link_libraries(netprobe
    ${PCAP_LIBRARY}
    ${JSONCPP_LIBRARIES}
    Pcap++ Packet++ Common++
    pcap
    pthread
    ${Boost_LIBRARIES}
    ${MYSQL_LIBRARIES}
)