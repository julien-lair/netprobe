# NetProbe - Documentation Technique

## Vue d'ensemble

NetProbe est une solution de cartographie réseau qui combine deux approches :
- Une cartographie passive basée sur l'analyse de paquets réseau
- Une cartographie active utilisant des scans et requêtes SNMP

## Architecture du système

### Module Passif (C++)

Le module passif est composé de plusieurs composants clés :

1. **CaptureManager** (`CaptureManager.hpp`)
   - Gère la capture de paquets sur une interface réseau
   - Distribue les paquets capturés aux différents analyseurs
   - Utilise la bibliothèque PcapPlusPlus pour la capture

2. **Analyseurs** (`Analyzers/`)
   - Protocoles supportés :
     - DHCP : Découverte des clients et serveurs DHCP
     - mDNS : Service discovery et noms d'hôtes
     - ARP : Découverte des adresses MAC
     - STP : Topologie des switches
     - SSDP : Découverte des services UPnP
     - CDP : Découverte des équipements Cisco
     - LLDP : Découverte des équipements réseau
     - WOL : Détection des paquets Wake-on-LAN
     - ICMP : Détection des pings et traceroutes
     - SNMP : Informations SNMP

3. **HostManager** (`Hosts/`)
   - Gestion des informations sur les hôtes découverts
   - Stockage dans une base de données MySQL
   - Export des données au format JSON

### Module Actif (Python)

Le module actif (`active/`) effectue des scans réseau et des requêtes SNMP pour compléter les informations obtenues passivement.

### Base de données

MySQL est utilisé pour stocker :
- Les hôtes découverts
- Les informations de topologie
- Les services détectés
- Les données SNMP

### Visualisation

Grafana est utilisé pour visualiser :
- La carte du réseau
- Les statistiques des hôtes
- L'évolution de la découverte
- Les métriques de performance

## Flux de données

1. Capture des paquets (CaptureManager)
2. Distribution aux analyseurs appropriés
3. Analyse et extraction des informations
4. Stockage dans la base de données
5. Enrichissement par le module actif
6. Visualisation dans Grafana

## Gestion des signaux

Le programme gère plusieurs signaux :
- SIGUSR1 : Déclenche l'export des données des hôtes
- SIGINT/SIGTERM : Arrêt propre du programme

## Variables d'environnement

- `INTERFACE` : Interface réseau à surveiller
- `TIMEOUT` : Durée de capture (-1 pour illimité)
- Variables de base de données (DB_HOST, DB_PORT, etc.)

## Performance et scalabilité

- Utilisation de threads pour la capture et l'analyse
- Gestion asynchrone des signaux avec Boost.Asio
- Optimisation de la capture avec PcapPlusPlus
