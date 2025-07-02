# 🚀 Flask IDS – Système de Détection d'Intrusion Réseau
## 📖 Introduction

Ce projet est un système de détection d'intrusion réseau basé sur Flask qui analyse les trames réseau (DHCP, ARP, ICMP, etc.) en utilisant des modèles de machine learning pour identifier des comportements anormaux.

## 🏗️ Structure du projet

```plaintext
├── anomalies.csv           # Anomalies détectées
├── Dockerfile              # Configuration Docker
├── main.py                 # Serveur Flask principal
├── models/                 # Modèles ML par protocole
│   ├── <PROTOCOL>/         # Ex: DHCP/
│   │   ├── df_normalized.* # Données d'entraînement
│   │   ├── feature_names.txt
│   │   ├── model_*.pkl     # Modèle KMeans
│   │   └── preprocessor.*  # Pipeline de prétraitement
├── trames.csv              # Dataset des trames collectées
└── Transformer.py          # Module de transformation
```

## 🔧 Installation

1. Cloner le dépôt
2. Installer les dépendances:
``` bash
pip install -r requirements.txt
```
## 🛠️ Phase 1: Création du Dataset

### 📡 Collecte des trames réseau

Utilisez l'endpoint suivant pour collecter les données pendant au moins 7 jours:

### Endpoint:

```text
POST /add_trames
```
### Fonctionnalité:

- Stocke les trames réseau dans un cache temporaire
- Flushe périodiquement dans trames.csv
- Génère le dataset pour l'entraînement
### Recommandations:

- Collectez des données sur une période représentative (min. 7 jours)
- Couvrez différents moments (jour/nuit, semaine/week-end) pour cela le programme doit tourner 24h/7j

### Où modifier le programme:
Rendez-vous dans ```../Hosts/HostManager.cpp``` modifier la ligne ```curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:5002/analyse");```par ```curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:5002/add_trames");```

## 🧠 Phase 2: Entraînement des modèles

Après la collecte:

1. Exécutez le script de création des modèles:
```bash
python create_model_proto_unique.py
```
### Ce script va:

1. Lire le fichier ```trames.csv```
2. Créer un modèle par protocole supporté
3. Sauvegarder les modèles dans ```models/<PROTOCOL>/```
### Protocoles supportés:

- DHCP, ARP, CDP, ICMP, LLDP
- SNMP, SSDP, STP, WOL, mDNS
## 🔍 Phase 3: Utilisation du système

### 🔎 Analyse des trames

### Endpoint:

```text
POST /analyse
```
### Fonctionnalité:

- Analyse une trame réseau en temps réel
- Compare avec le modèle du protocole correspondant
- Si anomalie détectée:
    - Stocke dans anomalies.csv

### Où modifier le programme:
Rendez-vous dans ```../Hosts/HostManager.cpp``` modifier la ligne ```curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:5002/add_trames");```par ```curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:5002/analyse");```

### Récupération des données malveillantes

### Endpoint: 

```text 
GET /get_csv
```

### Fonctionnalité: 

- Permet de récupérer le csv avec les trames malveillantes détecter
- Utiliser dans le modules Grafana pour afficher les alertes

## 📊 Visualisation (optionnel)

La fonction ```visualize_clusters_3d()``` permet de visualiser les clusters en 3D via PCA.

## 🐳 Déploiement avec Docker

Le serveur peut être déployé avec:

```bash
docker-compose up
```
ou en construisant l'image directement:

``` bash
docker build -t flask-ids .
docker run -p 5000:5000 flask-ids
```
## 🔐 Sécurité

- Verrous pour accès concurrent au cache
- Timestamp protégé pour calcul des deltas
- Données temporairement en cache avant écriture
## 📚 Dépendances principales

- Flask (serveur web)
- pandas/numpy (traitement de données)
- scikit-learn (ML et analyse)
- joblib (chargement des modèles)
- matplotlib (visualisation)