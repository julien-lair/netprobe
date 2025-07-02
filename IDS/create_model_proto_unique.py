import pandas as pd
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing import StandardScaler, OneHotEncoder, MinMaxScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.ensemble import RandomTreesEmbedding
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score

import joblib
import time
from datetime import timedelta
from tqdm import tqdm
from Transformer import TimestampTransformer, IpNormalizer, DnsTypeEncoder, ProtocolMapper, DhcpMessageMapper


def print_duration(start, label="⏱️ Durée"):
    duration = timedelta(seconds=time.time() - start)
    print(f"{label} : {duration}")

start_global = time.time()  # Chrono global

for proto_name_model in ["DHCP", "ARP", "CDP","ICMP","LLDP","SNMP","SSDP","STP","WOL","mDNS"]:
    # ==================================
    # 1. Chargement des données
    # ==================================
    start = time.time()
    print("📥 Chargement du fichier CSV...")
    df = pd.read_csv("trames.csv", sep=",")
    df['TARGET_MAC'] = df['TARGET_MAC'].fillna('00:00:00:00:00:00')

    # 🔍 Filtrage des lignes avec le protocole DHCP
    df = df[df['protocol'] == proto_name_model]
    print(f"✅ Données filtrées : {df.shape[0]} lignes avec le protocole {proto_name_model}, {df.shape[1]} colonnes")

    print(f"✅ Données chargées : {df.shape[0]} lignes, {df.shape[1]} colonnes")
    if df.shape[0] == 0:
        print(f"⚠️ Aucune donnée trouvée pour le protocole {proto_name_model}.")
        continue
    # ==================================
    # 2. Définition des colonnes
    # ==================================
    numeric_cols = ['taille', 'ICMP_TYPE', 'frames_10s', 'delta_ms']
    special_categorical_cols = ['DNS_TYPE']
    other_categorical_cols = ['SNMP_TYPE', 'SNMP_COMMUNITY_NAME']

    # ==================================
    # 3. Pipelines de transformation
    # ==================================
    print("🔧 Construction des pipelines de transformation...")

    numeric_pipeline = Pipeline([
        ('imputer', SimpleImputer(strategy='constant', fill_value=0)),
        ('scaler', MinMaxScaler(feature_range=(-1, 1)))
    ])

    categorical_pipeline = Pipeline([
        ('imputer', SimpleImputer(strategy='constant', fill_value='missing')),
        ('onehot', OneHotEncoder(handle_unknown='ignore'))
    ])

    timestamp_pipeline = Pipeline([
        ('ts_transform', TimestampTransformer(column='timestamp')),
        ('scaler', StandardScaler())
    ])

    # ==================================
    # 4. ColumnTransformer global
    # ==================================
    preprocessor = ColumnTransformer(
        transformers=[
            ('pass', 'passthrough', ['port_src', 'port_dst']),
            ('dhcp_server', IpNormalizer(column='DHCP_SERVER'), ['DHCP_SERVER']),
            ('dhcp_dns', IpNormalizer(column='DHCP_DNS'), ['DHCP_DNS']),
            ('num', numeric_pipeline, numeric_cols),
            ('dns_type', Pipeline([
                ('imputer', SimpleImputer(strategy='constant', fill_value='missing')),
                ('encoder', DnsTypeEncoder())
            ]), ['DNS_TYPE']),
            ('other_cat', categorical_pipeline, other_categorical_cols),
            ('ts', timestamp_pipeline, ['timestamp']),
            ('protocol', ProtocolMapper(column='protocol'), ['protocol']),
            ('dhcp_type', DhcpMessageMapper(column='DHCP_MESSAGE_TYPE'), ['DHCP_MESSAGE_TYPE']),
        ],
        remainder='drop'
    )

    # ==================================
    # 5. Transformation des données
    # ==================================

    print("🔄 Application des transformations...")
    X_processed = preprocessor.fit_transform(df)

    # ==================================
    # 6. Création des noms de colonnes
    # ==================================
    dhcp_server_columns = [f'dhcp_server_{i}' for i in range(4)]
    dhcp_dns_columns = [f'dhcp_dns_{i}' for i in range(4)]
    numeric_scaled_cols = [f'{col}_scaled' for col in numeric_cols]
    timestamp_columns = ['jour', 'heure', 'minute', 'seconde']

    onehot_columns = []
    if 'other_cat' in preprocessor.named_transformers_:
        onehot = preprocessor.named_transformers_['other_cat'].named_steps['onehot']
        onehot_columns = onehot.get_feature_names_out(other_categorical_cols)

    processed_columns = (
        ['port_src', 'port_dst'] +
        dhcp_server_columns + dhcp_dns_columns +
        numeric_scaled_cols + ['dns_type_encoded'] +
        list(onehot_columns) + timestamp_columns +
        ['protocol_mapped', 'dhcp_message_type_mapped']
    )

    # ==================================
    # 7. Création du DataFrame transformé
    # ==================================
    df_normalized = pd.DataFrame(X_processed, columns=processed_columns)
    print(f"✅ Données transformées. Dimensions : {df_normalized.shape}")

    # Sauvegarde intermédiaire
    df_normalized.to_pickle(f"models/{proto_name_model}/df_normalized.pkl") 
    df_normalized.to_csv(f"models/{proto_name_model}/df_normalized.csv", index=False)
    with open(f"models/{proto_name_model}/feature_names.txt", "w") as f:
        for name in df_normalized.columns:
            f.write(f"{name}\n")
    print("💾 Données normalisées sauvegardées.")
    print_duration(start, "⏱️ Temps")


    # ==================================
    # 7. Recherche du meilleur K
    # ==================================

    print("🔍 Recherche du meilleur K pour KMeans...")

    def find_best_k(X, max_k=60, sample_size=10000):
        scores = []
        X_sample = X if len(X) <= sample_size else X.sample(sample_size, random_state=42)

        for k in tqdm(range(2, max_k + 1), desc="Testing k values"):
            model = KMeans(
                n_clusters=k,
                random_state=42,
                n_init=10,           # ancien : 50
                init='k-means++',
                max_iter=2500,       # ancien : 3000
                tol=1e-6,
                verbose=0
            )
            preds = model.fit_predict(X_sample)
            score = silhouette_score(X_sample, preds)
            scores.append(score)

    

        best_k = scores.index(max(scores)) + 2
        print(f"Best K based on silhouette score (sample size={len(X_sample)}): {best_k}")
        return best_k

    X_normal = pd.read_pickle(f"models/{proto_name_model}/df_normalized.pkl")

    best_k = find_best_k(X_normal)




    # ==================================
    # 8. Embedding avec RandomTrees
    # ==================================
    print("🌲 Étape 1 : Embedding avec RandomTreesEmbedding...")
    start = time.time()

    # 💡 Modif : réduction du sample size pour éviter surcharge mémoire (ancien = len(df_normalized))
    sample_size = 300_000
    if len(df_normalized) <= sample_size:
        sample_size = len(df_normalized)
        print(f"⚠️ Taille de l'échantillon trop petite, utilisation de l'ensemble complet")
    X_sample = df_normalized.sample(sample_size, random_state=42)

    # 💡 Modif : réduction légère du nombre d’estimateurs (ancien = 40) et profondeur (ancien = 8)
    rt = RandomTreesEmbedding(
        n_estimators=300,     # ancien : 40
        max_depth=10,         # ancien : 8
        random_state=42
    )

    X_transformed_sparse = rt.fit_transform(X_sample)
    print(f"✅ Transformation terminée (sparse shape: {X_transformed_sparse.shape})")

    # 💡 Modif : conversion en dense partielle, uniquement si shape < seuil
    dense_limit = 10_000  # empirique, à adapter selon ta mémoire
    if X_transformed_sparse.shape[0] <= dense_limit:
        X_transformed = X_transformed_sparse.toarray()
        print(f"🧠 Données converties en dense : {X_transformed.shape} ({X_transformed.nbytes / 1e9:.2f} Go)")
    else:
        print("⚠️ Trop volumineux pour conversion en dense, utilisation sparse directe.")
        X_transformed = X_transformed_sparse  # reste en sparse

    joblib.dump(rt, f"models/{proto_name_model}/random_trees_embedder.pkl")
    print_duration(start, "⏱️ Temps pour RandomTreesEmbedding")

    # ==================================
    # 9. KMeans clustering
    # ==================================

    start = time.time()
    print("⚙️ Étape 2 : entraînement du  modèle KMeans...")

    # 💡 Modif : idem, réduction modérée du nombre de clusters et d’itérations (ancien k=50, max_iter=3000)
    kmeans2 = KMeans(
        n_clusters=best_k,       # ancien : 50
        random_state=42,
        n_init=80,           # ancien : 50
        init='k-means++',
        max_iter=2500,       # ancien : 3000
        tol=1e-6,
        verbose=0
    )
    kmeans2.fit(X_transformed)
    print("✅ second KMeans entraîné.")
    print_duration(start, "⏱️ Temps pour second KMeans")

    # ==================================
    # 10. Sauvegarde finale
    # ==================================
    print("💾 Sauvegarde du préprocesseur et du modèle...")
    joblib.dump(preprocessor, f'models/{proto_name_model}/preprocessor.pkl')
    joblib.dump(kmeans2, f'models/{proto_name_model}/model_{proto_name_model}.pkl')
    print(f"🎉 Modèle sauvegardé avec succès. Nombre de features finales : {len(df_normalized.columns)}")
