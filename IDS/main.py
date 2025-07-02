from flask import Flask, request, jsonify, send_file, Response
import io
import pandas as pd
import os
import csv
import threading
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import numpy as np
import joblib
from sklearn.metrics import pairwise_distances
from Transformer import TimestampTransformer, IpNormalizer, DnsTypeEncoder, ProtocolMapper, DhcpMessageMapper
import warnings
from mpl_toolkits.mplot3d import Axes3D
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
from dateutil import parser


app = Flask(__name__)
CSV_FILE = "trames.csv"
CACHE_FLUSH_INTERVAL = 2  # secondes
cache_lock = threading.Lock()
cache = []

# Pour gérer le delta global entre trames (dernière date reçue)
last_timestamp_global = None
last_timestamp_lock = threading.Lock()

# Pour stocker les timestamps par MAC, afin de compter les frames sur 10s
mac_timestamps = {}
mac_timestamps_lock = threading.Lock()

# Démarre le fichier s’il n’existe pas
if not os.path.exists(CSV_FILE):
    df = pd.DataFrame(columns=["timestamp", "protocol", "mac", "ip", "port_src", "port_dst", "taille",
                               "DHCP_SERVER","DHCP_DNS","DHCP_MESSAGE_TYPE","TARGET_IP","TARGET_MAC",
                               "ICMP_TYPE","DNS_TYPE","SNMP_TYPE","SNMP_COMMUNITY_NAME", "delta_ms", "frames_10s"])
    df.to_csv(CSV_FILE, index=False)

@app.route('/')
def index():
    return "Bienvenue sur le serveur IDS !"

@app.route('/add_trames', methods=['POST'])
#permet d'ajouter une trame au cache et de la stocker dans le fichier CSV 
#Cela permet de générer un dataset pour le futur apprentissage de notre modèle
def add_trames():
    global last_timestamp_global

    data = request.get_json()
    if not data:
        return jsonify({"error": "Paramètres manquants"}), 400

    protocol = data.get("protocol", "")
    details = data.get("data_protocol", {})
    DHCP_SERVER = ""
    DHCP_DNS = ""
    DHCP_MESSAGE_TYPE = ""
    TARGET_IP = ""
    TARGET_MAC = ""
    ICMP_TYPE = ""
    DNS_TYPE = ""
    SNMP_TYPE = ""
    SNMP_COMMUNITY_NAME = ""

    if protocol == "DHCP":
        DHCP_SERVER = details.get("DHCP_SERVER", "")
        DHCP_DNS = details.get("DNS", "")
        DHCP_MESSAGE_TYPE = details.get("MESSAGE_TYPE", "")
    elif protocol == "ARP":
        TARGET_IP = details.get("TARGET_IP", "")
    elif protocol == "ICMP":
        TARGET_IP = details.get("TARGET_IP", "")
        ICMP_TYPE = details.get("ICMP_TYPE", "")
    elif protocol == "mDNS":
        DNS_TYPE = details.get("TYPE", "")
    elif protocol == "SNMP":
        TARGET_MAC = details.get("TARGET_MAC", "")
        TARGET_IP = details.get("TARGET_IP", "")
        SNMP_TYPE = details.get("SNMP_TYPE", "")
        SNMP_COMMUNITY_NAME = details.get("COMMUNITY_NAME", "")

    now = datetime.now()
    day = now.strftime("%A")
    heure = now.strftime("%H:%M:%S")
    timestamp = f"{day} {heure}"

    # Calcul du delta temps (en millisecondes) depuis la dernière trame globale
    with last_timestamp_lock:
        if last_timestamp_global is None:
            delta_ms = 0
        else:
            delta = now - last_timestamp_global
            delta_ms = int(delta.total_seconds() * 1000)
        last_timestamp_global = now

    mac = data.get("mac", "")
    frames_10s = 1  # par défaut au moins la frame reçue

    # Mise à jour des timestamps par MAC
    with mac_timestamps_lock:
        if mac not in mac_timestamps:
            mac_timestamps[mac] = []
        # Ajout de la nouvelle date
        mac_timestamps[mac].append(now)
        # Nettoyer les timestamps plus vieux que 10 secondes
        cutoff = now - timedelta(seconds=10)
        mac_timestamps[mac] = [t for t in mac_timestamps[mac] if t >= cutoff]
        frames_10s = len(mac_timestamps[mac])

    with cache_lock:
        cache.append({
            "timestamp": timestamp,
            "protocol": protocol,
            "mac": mac,
            "ip": data.get("ip", ""),
            "port_src": data.get("port_src", ""),
            "port_dst": data.get("port_dst", ""),
            "taille": data.get("taille", ""),
            "DHCP_SERVER": DHCP_SERVER,
            "DHCP_DNS": DHCP_DNS,
            "DHCP_MESSAGE_TYPE": DHCP_MESSAGE_TYPE,
            "TARGET_IP": TARGET_IP,
            "TARGET_MAC": TARGET_MAC,
            "ICMP_TYPE": ICMP_TYPE,
            "DNS_TYPE": DNS_TYPE,
            "SNMP_TYPE": SNMP_TYPE,
            "SNMP_COMMUNITY_NAME": SNMP_COMMUNITY_NAME,
            "delta_ms": delta_ms,
            "frames_10s": frames_10s
        })

    return jsonify({"message": "Trame ajoutée en cache", "delta_ms": delta_ms, "frames_10s": frames_10s}), 200

def flush_cache():
    while True:
        time.sleep(CACHE_FLUSH_INTERVAL)
        with cache_lock:
            if cache:
                df = pd.DataFrame(cache)
                df.to_csv(CSV_FILE, mode='a', header=False, index=False)
                cache.clear()

flusher_thread = threading.Thread(target=flush_cache, daemon=True)
flusher_thread.start()
    
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning)

pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)
pd.set_option('display.max_colwidth', None)

# === CLASSES ===

class DataCleaner:
    @staticmethod
    def clean_dhcp_message(message):
        s = str(message).strip()
        if s:
            return s.split()[0].split('(')[0].upper()
        return ""

    
    @staticmethod
    def clean_raw_data(raw_data):
        expected_columns = [
            'timestamp', 'protocol', 'mac', 'port_src', 'port_dst', 'taille',
            'DHCP_SERVER', 'DHCP_DNS', 'DHCP_MESSAGE_TYPE', 'TARGET_MAC',
            'ICMP_TYPE', 'DNS_TYPE', 'SNMP_TYPE', 'SNMP_COMMUNITY_NAME',
            'delta_ms', 'frames_10s'
        ]
        df = pd.DataFrame(raw_data, columns=expected_columns)
        df['TARGET_MAC'] = df['TARGET_MAC'].fillna('00:00:00:00:00:00')
        df['DHCP_MESSAGE_TYPE'] = df['DHCP_MESSAGE_TYPE'].apply(DataCleaner.clean_dhcp_message)
        return df

# === MODELES ===

MODELS_PATH = "models"
modeles = {}
threshold_cache = {}

def load_models():
    protocols = ['DHCP', 'ARP', 'CDP', 'ICMP', 'LLDP', 'SNMP', 'SSDP', 'STP', 'WOL', 'mDNS']
    for proto in protocols:
        path = os.path.join(MODELS_PATH, proto)
        preproc_path = os.path.join(path, "preprocessor.pkl")
        model_path = os.path.join(path, f"model_{proto}.pkl")
        rt_path = os.path.join(path, "random_trees_embedder.pkl")
        df_normalized = os.path.join(path, "df_normalized.pkl")

        if all(os.path.exists(p) for p in [preproc_path, model_path, rt_path]):
            modeles[proto] = {
                'preprocessor': joblib.load(preproc_path),
                'kmeans': joblib.load(model_path),
                'rt': joblib.load(rt_path),
                'df_normalized': joblib.load(df_normalized),
                'threshold': 0
            }
        else:
            missing = [p for p in [preproc_path, model_path, rt_path] if not os.path.exists(p)]
            print(f"⚠️ Fichiers manquants pour le protocole {proto} : {', '.join(missing)}")

load_models()



# === PCA VISUALISATION ===
def visualize_clusters_3d(protocol, X_train_transformed, test_points, clusters, distances, threshold, max_points=1000):
    kmeans = modeles[protocol]['kmeans']
    cluster_centers = kmeans.cluster_centers_

    # Fit PCA à 3 composantes
    pca = PCA(n_components=3)
    X_train_pca = pca.fit_transform(X_train_transformed)
    centers_pca = pca.transform(cluster_centers)
    test_pca = pca.transform(test_points)

    # Échantillonnage aléatoire des points d'entraînement (si trop nombreux)
    if len(X_train_pca) > max_points:
        indices = np.random.choice(len(X_train_pca), size=max_points, replace=False)
        X_train_pca_sampled = X_train_pca[indices]
    else:
        X_train_pca_sampled = X_train_pca

    fig = plt.figure(figsize=(10, 8))
    ax = fig.add_subplot(111, projection='3d')

    # Affichage des données échantillonnées
    ax.scatter(X_train_pca_sampled[:, 0], X_train_pca_sampled[:, 1], X_train_pca_sampled[:, 2], 
               c='lightgray', alpha=0.4, label='Données normalisées (échantillon)')

    # Centres des clusters
    ax.scatter(centers_pca[:, 0], centers_pca[:, 1], centers_pca[:, 2],
               c='blue', marker='X', s=200, label='Centres des clusters')

    # Points test
    for i, point in enumerate(test_pca):
        color = 'red' if distances[i] > threshold else 'green'
        ax.scatter(point[0], point[1], point[2],
                   c=color, edgecolors='black', s=150, marker='o',
                   label='Valeur test' if i == 0 else "")

        cluster_id = clusters[i]
        center = centers_pca[cluster_id]
        ax.plot([point[0], center[0]], [point[1], center[1]], [point[2], center[2]], 
                c='black', linestyle='--', alpha=0.3)

    ax.set_title(f"Projection PCA 3D des clusters pour le protocole {protocol}")
    ax.legend(loc='best')
    plt.tight_layout()
    plt.show()

# === ANALYSE ANOMALIES ===

def compute_threshold(protocol):
    if protocol in threshold_cache:
        return threshold_cache[protocol]
    
    rt = modeles[protocol]['rt']
    kmeans = modeles[protocol]['kmeans']
    df_normalized = modeles[protocol]['df_normalized']
    X = df_normalized
    X_transformed = rt.transform(X)
    clusters = kmeans.predict(X_transformed)
    distances_matrix = pairwise_distances(X_transformed, kmeans.cluster_centers_, metric='euclidean')
    distances = distances_matrix[np.arange(len(clusters)), clusters]
    threshold = np.percentile(distances, 95)
    threshold_cache[protocol] = threshold * 1.05
    print(f"---------___> ✅ Seuil pour le protocole {protocol} : {threshold * 1.1:.4f}")

    return threshold * 1.05 # Augmenter le seuil de 5% pour plus de robustesse

def detect_anomalies(df, protocol):
    preprocessor = modeles[protocol]['preprocessor']
    kmeans = modeles[protocol]['kmeans']
    rt = modeles[protocol]['rt']
    threshold = compute_threshold(protocol)

    X = preprocessor.transform(df)
    X_transformed = rt.transform(X)
    clusters = kmeans.predict(X_transformed)
    distances_matrix = pairwise_distances(X_transformed, kmeans.cluster_centers_, metric='euclidean')
    distances = distances_matrix[np.arange(len(clusters)), clusters]

    # visualize_clusters_3d(
    #     protocol,
    #     modeles[protocol]['rt'].transform(modeles[protocol]['df_normalized']),
    #     X_transformed,
    #     clusters,
    #     distances,
    #     threshold
    # )

    df['is_anomaly'] = distances > threshold
    df['distance'] = distances
    df['cluster'] = clusters

    return df[['is_anomaly', 'distance', 'cluster']].to_dict(orient='records')

def analyze_traffic(raw_data):
    df = DataCleaner.clean_raw_data(raw_data)
    protocol = df['protocol'].iloc[0]

    if protocol not in modeles:
        raise ValueError(f"⚠️ Protocole {protocol} non supporté.")
    
    results = detect_anomalies(df, protocol)

    for i in range(len(df)):
        df.at[i, 'is_anomaly'] = results[i]['is_anomaly']
        df.at[i, 'distance'] = results[i]['distance']
        df.at[i, 'cluster'] = results[i]['cluster']
    
    return df.to_dict(orient='records')


analysis_times = []
analysis_times_lock = threading.Lock()

@app.route('/analyse', methods=['POST'])
def analyse():
    global last_timestamp_global
    start_time = time.time()
    data = request.get_json()
    if not data:
        return jsonify({"error": "Paramètres manquants"}), 400

    protocol = data.get("protocol", "")
    details = data.get("data_protocol", {})
    
    # Extraction des champs spécifiques selon protocole
    DHCP_SERVER = details.get("DHCP_SERVER", "")
    DHCP_DNS = details.get("DNS", "")
    DHCP_MESSAGE_TYPE = details.get("MESSAGE_TYPE", "")
    TARGET_IP = details.get("TARGET_IP", "")
    TARGET_MAC = details.get("TARGET_MAC", "")
    ICMP_TYPE = details.get("ICMP_TYPE", "")
    DNS_TYPE = details.get("TYPE", "")
    SNMP_TYPE = details.get("SNMP_TYPE", "")
    SNMP_COMMUNITY_NAME = details.get("COMMUNITY_NAME", "")


    #Gestion des temps pour delta_ms et frames_10s
    now = datetime.now()
    day = now.strftime("%A")
    heure = now.strftime("%H:%M:%S")
    timestamp = f"{day} {heure}"

    # Calcul du delta temps (en millisecondes) depuis la dernière trame globale
    with last_timestamp_lock:
        if last_timestamp_global is None:
            delta_ms = 0
        else:
            delta = now - last_timestamp_global
            delta_ms = int(delta.total_seconds() * 1000)
        last_timestamp_global = now

    mac = data.get("mac", "")
    frames_10s = 1  # par défaut au moins la frame reçue

    # Mise à jour des timestamps par MAC
    with mac_timestamps_lock:
        if mac not in mac_timestamps:
            mac_timestamps[mac] = []
        # Ajout de la nouvelle date
        mac_timestamps[mac].append(now)
        # Nettoyer les timestamps plus vieux que 10 secondes
        cutoff = now - timedelta(seconds=10)
        mac_timestamps[mac] = [t for t in mac_timestamps[mac] if t >= cutoff]
        frames_10s = len(mac_timestamps[mac])

    received_timestamp_str = datetime.now().strftime("%A %H:%M:%S")
    received_timestamp = None
    if received_timestamp_str:
        try:
            received_timestamp = parser.parse(received_timestamp_str)
        except Exception:
            received_timestamp = None
    # Création d’une seule trame à analyser (forme dict)
    trame = {
        "timestamp": datetime.now().strftime("%A %H:%M:%S"),
        "protocol": protocol,
        "mac": data.get("mac", ""),
        "port_src": data.get("port_src", ""),
        "port_dst": data.get("port_dst", ""),
        "taille": data.get("taille", ""),
        "DHCP_SERVER": DHCP_SERVER,
        "DHCP_DNS": DHCP_DNS,
        "DHCP_MESSAGE_TYPE": DHCP_MESSAGE_TYPE,
        "TARGET_MAC": TARGET_MAC,
        "ICMP_TYPE": ICMP_TYPE,
        "DNS_TYPE": DNS_TYPE,
        "SNMP_TYPE": SNMP_TYPE,
        "SNMP_COMMUNITY_NAME": SNMP_COMMUNITY_NAME,
        "delta_ms": delta_ms,
        "frames_10s": frames_10s
    }

    # 🔧 Remplacer toutes les chaînes vides par np.nan
    for key, value in trame.items():
        if value == "":
            trame[key] = np.nan
    try:
        
        results = analyze_traffic([trame])
        is_anomaly = results[0]["is_anomaly"]
        distance = results[0]["distance"]

        #on regarde le temps que ça a pris  
        end_time = time.time()
        duration_s = end_time - start_time  # On garde la valeur brute non arrondie

        with analysis_times_lock:
            analysis_times.append(duration_s)
            if len(analysis_times) > 1000:  # garder les 1000 dernières analyses
                analysis_times.pop(0)
            moyenne = sum(analysis_times) / len(analysis_times)
        delay_s = None
        if received_timestamp:
            delay_s = (now - received_timestamp).total_seconds()
            delay_str = f"⏱️ Retard de traitement : {delay_s:.2f} s"
        else:
            delay_str = "⏱️ Timestamp non fourni ou invalide"
        # Pour affichage : on arrondit juste au moment d'imprimer
        if is_anomaly:
            print('-'*40)
            print(f"⚠️ Anomalie détectée — Analyse en {duration_s:.3f} s - ({delay_str})")
            #print(f"Distance observé : {distance}  --  Distance threshold {protocol} {threshold_cache[protocol]}")
            print(trame)
            #on enregistre la trames dans un csv 
            csv_file = "anomalies.csv"
    
            # On vérifie si le fichier existe déjà pour écrire l'en-tête ou non
            file_exists = os.path.isfile(csv_file)
            
            # Ouvrir le fichier en mode append
            with open(csv_file, mode='a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=trame.keys())
                
                # Écrire l'en-tête si le fichier est vide / vient d'être créé
                if not file_exists:
                    writer.writeheader()
                
                # Écrire la ligne correspondante à la trame
                paris_time = datetime.now(ZoneInfo("Europe/Paris"))
                trame["timestamp"] = paris_time.isoformat()
                writer.writerow(trame)


        return jsonify({"anomaly": is_anomaly}), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.route('/get_csv', methods=['GET'])
def get_csv():
    filename = f"anomalies.csv"
    
    if not os.path.exists(filename):
        return jsonify({"error": "Fichier non trouvé"}), 404
        
    # Configuration pour Grafana
    if 'grafana' in request.args:
        df = pd.read_csv(filename)
        
        # Formatage spécifique pour Grafana
        if 'timestamp' in df.columns:
            df['time'] = pd.to_datetime(df['timestamp'], format='%A %H:%M:%S')
            df = df.set_index('time')
            
        output = io.StringIO()
        df.to_csv(output)
        output.seek(0)
        
        return Response(
            output,
            mimetype="text/csv",
            headers={"Content-disposition": f"attachment; filename={filename}"}
        )
    else:
        # Retour normal du fichier CSV
        return send_file(filename, as_attachment=True)

        
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002)
