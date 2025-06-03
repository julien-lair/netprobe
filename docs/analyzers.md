# Guide des analyseurs de protocoles

## Vue d'ensemble

Les analyseurs sont des composants clés de NetProbe qui traitent les paquets réseau pour en extraire des informations pertinentes. Chaque analyseur est spécialisé dans un protocole spécifique.

## Architecture des analyseurs

### Classe de base Analyzer

Tous les analyseurs héritent de la classe de base `Analyzer` :

```cpp
class Analyzer {
protected:
    HostManager& hostManager;

public:
    Analyzer(HostManager& manager) : hostManager(manager) {}
    virtual ~Analyzer() {}
    virtual void analyzePacket(pcpp::Packet& packet) = 0;
};
```

## Analyseurs disponibles

### 1. DHCP Analyzer
- **Fichier** : `Analyzers/DHCP/DHCPAnalyzer.hpp`
- **Fonction** : Détection des clients et serveurs DHCP
- **Informations collectées** :
  - Adresses IP attribuées
  - Durée des baux
  - Options DHCP (nom d'hôte, domaine, etc.)

### 2. mDNS Analyzer
- **Fichier** : `Analyzers/mDNS/mDNSAnalyzer.hpp`
- **Fonction** : Découverte des services multicast DNS
- **Informations collectées** :
  - Noms d'hôtes
  - Services annoncés
  - Adresses IP locales

### 3. ARP Analyzer
- **Fichier** : `Analyzers/ARP/ARPAnalyzer.hpp`
- **Fonction** : Analyse du protocole ARP
- **Informations collectées** :
  - Correspondances MAC/IP
  - Détection des conflits ARP
  - Identification des passerelles

### 4. STP Analyzer
- **Fichier** : `Analyzers/STP/STPAnalyzer.hpp`
- **Fonction** : Analyse du Spanning Tree Protocol
- **Informations collectées** :
  - Topologie des switches
  - Root bridges
  - Ports bloqués/forwarding

### 5. SSDP Analyzer
- **Fichier** : `Analyzers/SSDP/SSDPAnalyzer.hpp`
- **Fonction** : Découverte des services UPnP
- **Informations collectées** :
  - Types de périphériques
  - Services disponibles
  - URLs des descriptions

### 6. CDP Analyzer
- **Fichier** : `Analyzers/CDP/CDPAnalyzer.hpp`
- **Fonction** : Analyse du Cisco Discovery Protocol
- **Informations collectées** :
  - Modèles d'équipements Cisco
  - Versions IOS
  - Informations de VLAN

### 7. LLDP Analyzer
- **Fichier** : `Analyzers/LLDP/LLDPAnalyzer.hpp`
- **Fonction** : Analyse du Link Layer Discovery Protocol
- **Informations collectées** :
  - Capacités des équipements
  - Informations de port
  - Management addresses

### 8. WOL Analyzer
- **Fichier** : `Analyzers/WOL/WOLAnalyzer.hpp`
- **Fonction** : Détection des paquets Wake-on-LAN
- **Informations collectées** :
  - MAC addresses cibles
  - Sources des requêtes

### 9. ICMP Analyzer
- **Fichier** : `Analyzers/ICMP/ICMPAnalyzer.hpp`
- **Fonction** : Analyse des paquets ICMP
- **Informations collectées** :
  - Types de messages ICMP
  - Latence réseau
  - Traceroutes

### 10. SNMP Analyzer
- **Fichier** : `Analyzers/SNMP/SNMPAnalyzer.hpp`
- **Fonction** : Analyse du Simple Network Management Protocol
- **Informations collectées** :
  - OIDs interrogés
  - Versions SNMP
  - Communautés utilisées

## Ajout d'un nouvel analyseur

1. **Création du fichier**
   ```bash
   mkdir -p Analyzers/NewProtocol
   touch Analyzers/NewProtocol/NewProtocolAnalyzer.hpp
   ```

2. **Structure de base**
   ```cpp
   class NewProtocolAnalyzer : public Analyzer {
   public:
       NewProtocolAnalyzer(HostManager& manager) : Analyzer(manager) {}
       void analyzePacket(pcpp::Packet& packet) override {
           // Implémentation de l'analyse
       }
   };
   ```

3. **Intégration**
   - Ajouter l'include dans main.cpp
   - Créer une instance dans main()
   - Ajouter l'analyseur au CaptureManager

4. **Bonnes pratiques**
   - Vérifier la validité des paquets
   - Gérer les erreurs proprement
   - Documenter le code
   - Ajouter des tests unitaires