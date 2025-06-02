# -----------------------------
# Étape 1 : Compilation (Build)
# -----------------------------
FROM alpine:latest AS build

# Installation des dépendances nécessaires à la compilation de l'application
RUN apk add --no-cache \
    g++ \
    cmake \
    make \
    libpcap-dev \
    linux-headers \
    git \
    wget \
    curl \
    jsoncpp-dev \
    boost-dev \
    mariadb-connector-c-dev \
    mariadb-dev \
    mysql-client \
    mariadb-connector-c

# Installation de la glibc (certains outils l'exigent)
RUN wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub \
    && wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.35-r1/glibc-2.35-r1.apk \
    && apk add --no-cache --allow-untrusted glibc-2.35-r1.apk \
    && rm glibc-2.35-r1.apk

# Téléchargement et installation de la librairie PcapPlusPlus
RUN wget https://github.com/seladb/PcapPlusPlus/archive/v24.09.tar.gz \
    && tar -xf v24.09.tar.gz \
    && rm v24.09.tar.gz \
    && cd PcapPlusPlus-24.09 \
    && cmake -S . -B build \
    && cmake --build build \
    && cmake --install build --prefix /usr/local

# Répertoire de travail pour ton projet
WORKDIR /netprobe

# Copie des fichiers sources de ton projet dans l'image
COPY Analyzers /netprobe/Analyzers
COPY Layers /netprobe/Layers
COPY Hosts /netprobe/Hosts
COPY CaptureManager.hpp /netprobe/CaptureManager.hpp
COPY main.cpp /netprobe/main.cpp
COPY CMakeLists.txt /netprobe/CMakeLists.txt
COPY FindPCAP.cmake /netprobe/FindPCAP.cmake
COPY Scripts /netprobe/Scripts

# Compilation du projet C++
RUN mkdir build \
    && cd build \
    && cmake -DCMAKE_PREFIX_PATH=/usr/local -DCMAKE_BUILD_TYPE=Debug .. \
    && cmake --build .

# -------------------------------
# Étape 2 : Runtime (Exécution)
# -------------------------------
    FROM alpine:latest

    # Installation des dépendances nécessaires à l'exécution du binaire et serveur web
    RUN apk add --no-cache \
        libpcap \
        jsoncpp \
        boost-system \
        boost-thread \
        shadow \
        wget \
        net-snmp-tools \
        python3 \
        py3-pip \
        mariadb-connector-c \
        mysql-client
    
    # Installation de la glibc pour l'exécution correcte de certains outils
    RUN wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub \
        && wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.35-r1/glibc-2.35-r1.apk \
        && apk add --no-cache --allow-untrusted glibc-2.35-r1.apk \
        && rm glibc-2.35-r1.apk
    
    # Téléchargement manuel des MIBs SNMP nécessaires aux outils de supervision
    RUN mkdir -p /usr/share/snmp/mibs \
        && wget -q -O /usr/share/snmp/mibs/IANAifType-MIB https://mibs.pysnmp.com/asn1/IANAifType-MIB \
        && wget -q -O /usr/share/snmp/mibs/IF-MIB https://mibs.pysnmp.com/asn1/IF-MIB \
        && wget -q -O /usr/share/snmp/mibs/IP-MIB https://mibs.pysnmp.com/asn1/IP-MIB \
        && [ -f /etc/snmp/snmp.conf ] && sed -i 's/^mibs/#mibs/' /etc/snmp/snmp.conf || true
    
    # Copie des fichiers compilés depuis l'étape build
    COPY --from=build /netprobe/Hosts/manuf /netprobe/build/manuf
    COPY --from=build /netprobe/build /netprobe/build
    COPY --from=build /netprobe/Scripts /netprobe/Scripts
    # Répertoire de travail
    WORKDIR /netprobe
    
    # Copie de vos fichiers HTML et JSON dans le conteneur
    
    # Commande de démarrage du conteneur
    CMD ["sh", "-c", "./build/netprobe"]