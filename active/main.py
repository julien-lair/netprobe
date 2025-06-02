import subprocess
from flask import Flask, request, jsonify, make_response, Response
import json
import os
import mysql.connector
from datetime import datetime, timedelta
import re
import uuid

app = Flask(__name__)

""" 
Fonction pour vérifier si une chaîne de caractères est une IP valide ou un CIDR /24.
@param ip_str: Chaîne de caractères représentant une IP ou un CIDR.
@return: True si la chaîne est une IP valide ou un CIDR /24, False sinon.
"""
def is_valid_ip_or_cidr(ip_str):
    # Match une IP IPv4 seule
    ipv4_regex = r'^(\d{1,3}\.){3}\d{1,3}$'
    # Match un CIDR /24 uniquement
    cidr_24_regex = r'^(\d{1,3}\.){3}\d{1,3}/24$'

    # Vérification regex
    if re.match(ipv4_regex, ip_str):
        parts = list(map(int, ip_str.split('.')))
        return all(0 <= part <= 255 for part in parts)

    if re.match(cidr_24_regex, ip_str):
        ip_part = ip_str.split('/')[0]
        parts = list(map(int, ip_part.split('.')))
        return all(0 <= part <= 255 for part in parts)

    return False


""" 
Fonction pour découper des objets JSON imbriqués dans un texte non formaté.
@param text: Chaîne de caractères contenant des objets JSON imbriqués.
@return: Liste de chaînes de caractères, chaque chaîne étant un objet JSON extrait du texte.
"""
def split_json_objects(text):
    """Découpe les objets JSON imbriqués dans un texte non formatté en liste."""
    objects = []
    brace_count = 0
    start_idx = None

    for i, char in enumerate(text):
        if char == '{':
            if brace_count == 0:
                start_idx = i
            brace_count += 1
        elif char == '}':
            brace_count -= 1
            if brace_count == 0 and start_idx is not None:
                objects.append(text[start_idx:i+1])
                start_idx = None

    return objects

""" 
Route pour vérifier les cibles ARP dans la base de données.
@return: JSON contenant les adresses MAC et IP des cibles ARP nécessaires.
"""
@app.route("/arp-check")
def check_arp_targets():
    try:
        conn = mysql.connector.connect(
            host=os.environ["DB_HOST"],
            port=int(os.environ.get("DB_PORT", 3306)),
            user=os.environ["DB_USER"],
            password=os.environ["DB_PASSWORD"],
            database=os.environ["DB_NAME"]
        )
        cursor = conn.cursor(dictionary=True)

        # Obtenir les IP connues
        cursor.execute("SELECT ip FROM hosts;")
        known_ips = set(row["ip"] for row in cursor.fetchall() if row["ip"])

        # Obtenir les données contenant ARP
        six_hours_ago = int((datetime.now() - timedelta(hours=6)).timestamp())

        cursor.execute("""SELECT mac, data FROM hosts WHERE protocole LIKE '%arp%' AND last_seen >= %s""", (six_hours_ago,))
        rows = cursor.fetchall()
        arp_needed = []

        for row in rows:
            raw_data = row["data"]
            json_blobs = split_json_objects(raw_data)

            for obj in json_blobs:
                try:
                    entry = json.loads(obj)
                except json.JSONDecodeError:
                    continue

                if entry.get("PROTOCOL") == "ARP":
                    sender_mac = entry.get("SENDER_MAC")
                    sender_ip = entry.get("SENDER_IP")
                    target_ip = entry.get("TARGET_IP")

                    if target_ip and target_ip not in known_ips:
                        #si arp_needed contient dejà la même from_ip et target_ip, on ne l'ajoute pas
                        if not any(
                            item["from_mac"] == sender_mac and
                            item["target_ip"] == target_ip
                            for item in arp_needed
                        ):
                        # Ajouter à la liste des ARP nécessaires
                            arp_needed.append({
                                "from_mac": sender_mac,
                                "from_ip": sender_ip,
                                "target_ip": target_ip
                            })
                            

        cursor.close()
        conn.close()

        return jsonify(arp_needed)

    except Exception as e:
        return jsonify({"error": str(e)}), 500
        

""" 
Fonction pour ajouter les en-têtes CORS à la réponse.
@param response: Objet de réponse Flask.
@return: Objet de réponse Flask avec les en-têtes CORS ajoutés.
"""
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'  # Ou mettre l'origine précise au lieu de '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
    return response

"""
Route pour lancer la commande arping.
@param: IP à vérifier.
@return: JSON contenant le résultat de la commande arping.
"""
@app.route('/arp/', methods=['POST', 'OPTIONS'])
def arp():
    if request.method == 'OPTIONS':
        resp = make_response()
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
        resp.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
        return resp

    data = request.get_json()
    ip = data.get('ip')
    if not ip:
        return jsonify({'output': 'IP manquante'}), 400
    if not is_valid_ip_or_cidr(ip):
        return jsonify({'output': 'Format IP invalide. Seules les IPv4 ou /24 sont acceptées.'}), 400

    try:
        result = subprocess.run(
            ['arping', '-c', '3', '-w', '5', ip],
            capture_output=True,
            text=True,
            timeout=10
        )
        commande = f">>> arping -c 3 -w 5 {ip} \n"
        output = commande + result.stdout + result.stderr

        return jsonify({
            'message': f'ARP lancé sur {ip}',
            'output': output
        })
    except subprocess.TimeoutExpired:
        return jsonify({'output': 'Timeout lors de la commande arping'}), 504
    except Exception as e:
        return jsonify({'output': str(e)}), 500



""" 
Route pour lancer la commande mDNS.
@return: JSON contenant le résultat de la commande mDNS.
"""
@app.route('/mdns/', methods=['GET', 'OPTIONS'])
def mdns():
    if request.method == 'OPTIONS':
        resp = make_response()
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
        resp.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
        return resp

    try:
        result = subprocess.run(
            ['timeout', '10s', 'avahi-browse', '-art'],
            capture_output=True,
            text=True,
            timeout=15
        )
        commande = ">>> timeout 10s avahi-browse -art\n"

        output = commande + result.stdout + result.stderr

        return jsonify({
            'message': f'mDNS lancé',
            'output': output
        })
    except subprocess.TimeoutExpired:
        return jsonify({'output': 'Timeout lors de la commande mDNS'}), 504
    except Exception as e:
        return jsonify({'output': str(e)}), 500


"""
Route pour lancer la commande SNMP.
@param: IP et community SNMP.
@return: JSON contenant le résultat de la commande SNMP.
"""
@app.route('/snmp1/', methods=['POST', 'OPTIONS'])
def snmp1():
    if request.method == 'OPTIONS':
        resp = make_response()
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
        resp.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
        return resp

    data = request.get_json()
    ip = data.get('ip')
    community = data.get('community')
    if not ip or not community:
        return jsonify({'output': 'IP manquante ou community manquante'}), 400
    if not is_valid_ip_or_cidr(ip):
        return jsonify({'output': 'Format IP invalide. Seules les IPv4 ou /24 sont acceptées.'}), 400
    
    try:
        result = subprocess.run(
            ['./snmp.sh', ip, community],
            capture_output=True,
            text=True,
            timeout=30
        )
        commande = f">>> ./snmp.sh {ip} {community}\n"
        output = commande + result.stdout + result.stderr

        return jsonify({
            'message': f'SNMP lancé sur {ip} et community : {community}',
            'output': output
        })
    except subprocess.TimeoutExpired:
        return jsonify({'output': 'Timeout lors de la commande arping'}), 504
    except Exception as e:
        return jsonify({'output': str(e)}), 500

"""
Route pour lancer la commande SNMP sur le port 161.
@param: IP à vérifier.
@return: JSON contenant le résultat de la commande SNMP.
"""
@app.route('/snmp2/', methods=['POST', 'OPTIONS'])
def snmp2():
    if request.method == 'OPTIONS':
        resp = make_response()
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
        resp.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
        return resp

    data = request.get_json()
    ip = data.get('ip')
    
    if not ip:
        return jsonify({'output': 'IP manquante'}), 400
    if not is_valid_ip_or_cidr(ip):
        return jsonify({'output': 'Format IP invalide. Seules les IPv4 ou /24 sont acceptées.'}), 400

    try:

        result = subprocess.run(
            ['nmap', '-sU', '-p', '161', '--open', '--script=snmp-info', ip],
            capture_output=True,
            text=True,
            timeout=30
        )
        commande = f">>> nmap -sU -p 161 --open --script=snmp-info {ip} \n"
        output = commande + result.stdout + result.stderr

        return jsonify({
            'message': f'SNMP lancé sur {ip}',
            'output': output
        })
    except subprocess.TimeoutExpired:
        return jsonify({'output': 'Timeout lors de la commande arping'}), 504
    except Exception as e:
        return jsonify({'output': str(e)}), 500


"""
Route pour lancer la commande HTTP/HTTPS.
@param: IP à vérifier.
@return: JSON contenant le résultat de la commande HTTP/HTTPS.
"""
@app.route('/https/', methods=['POST', 'OPTIONS'])
def https():
    if request.method == 'OPTIONS':
        resp = make_response()
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
        resp.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
        return resp

    data = request.get_json()
    ip = data.get('ip')
    
    if not ip:
        return jsonify({'output': 'IP manquante'}), 400
    # if not is_valid_ip_or_cidr(ip):
    #     return jsonify({'output': 'Format IP invalide. Seules les IPv4 ou /24 sont acceptées.'}), 400

    try:

        result = subprocess.run(
            ['nmap', '-p', '80,443,8000-9000', '--open', '-sS', ip],
            capture_output=True,
            text=True,
            timeout=36000
        )
        commande = f">>> nmap -p 80,443,8000-9000 --open -sS {ip} \n"
        output = commande + result.stdout + result.stderr

        # return jsonify({
        #     'message': f'Http lancé sur {ip}',
        #     'output': output
        # })
        return Response(
        json.dumps({
            'message': f'Http lancé sur {ip}',
            'output': output,
            'truncated': False
        }),
        mimetype='application/json',
        headers={'Content-Length': str(len(output))}
        )

    except subprocess.TimeoutExpired:
        return jsonify({'output': 'Timeout lors de la commande arping'}), 504
    except Exception as e:
        return jsonify({'output': str(e)}), 500

"""
Route pour lancer la commande SSH.
@param: IP à vérifier.
@return: JSON contenant le résultat de la commande SSH.
"""
@app.route('/ssh/', methods=['POST', 'OPTIONS'])
def ssh():
    if request.method == 'OPTIONS':
        resp = make_response()
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
        resp.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
        return resp

    data = request.get_json()
    ip = data.get('ip')
    
    if not ip:
        return jsonify({'output': 'IP manquante'}), 400
    if not is_valid_ip_or_cidr(ip):
        return jsonify({'output': 'Format IP invalide. Seules les IPv4 ou /24 sont acceptées.'}), 400

    try:

        result = subprocess.run(
            ['nmap', '-p', '22', '--open', '-sS', '-sV', ip],
            capture_output=True,
            text=True,
            timeout=30
        )
        commande = f">>> nmap -p 22 --open -sS -sV {ip} \n"
        output = commande + result.stdout + result.stderr

        return jsonify({
            'message': f'Http lancé sur {ip}',
            'output': output
        })
    except subprocess.TimeoutExpired:
        return jsonify({'output': 'Timeout lors de la commande arping'}), 504
    except Exception as e:
        return jsonify({'output': str(e)}), 500



def generate_node(mac, returnEdges = False):
    try:
        conn = mysql.connector.connect(
            host=os.environ["DB_HOST"],
            port=int(os.environ.get("DB_PORT", 3306)),
            user=os.environ["DB_USER"],
            password=os.environ["DB_PASSWORD"],
            database=os.environ["DB_NAME"]
        )
        cursor = conn.cursor(dictionary=True)

        node = []
        liste_ip = []
        liste_ip2 = []
        already_add = []
        edges = []
        cursor.execute("""SELECT * FROM hosts WHERE mac = %s""", (mac,))
        rows = cursor.fetchall()
        for row in rows:
            mac = re.sub(r"[\s,]+", "|", row["mac"].strip())
            ip = re.sub(r"[\s,]+", "|", row["ip"].strip())
            hostname = re.sub(r"[\s,]+", "|", row["hostname"].strip())
            vendor = re.sub(r"[\s,]+", "|", row["vendor"].strip())
            OS = re.sub(r"[\s,]+", "|", row["OS"].strip())
            protocole = re.sub(r"[\s,]+", "|", row["protocole"].strip())

            data = row["data"]

            if ip not in already_add:
                node.append({
                    "id": ip,
                    "title": hostname,
                    "subtitle": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "OS": OS,
                    "protocole": protocole,
                    "color": "green",
                    "highlighted": True,
                })
                already_add.append(ip)

            json_blobs = split_json_objects(data)
            for obj in json_blobs:
                try:
                    entry = json.loads(obj)
                except json.JSONDecodeError:
                    continue
                if entry.get("PROTOCOL") == "ARP":
                    sender_ip = entry.get("SENDER_IP")
                    target_ip = entry.get("TARGET_IP")
                    if sender_ip != target_ip and target_ip not in liste_ip:
                        liste_ip.append(target_ip)
                        edges.append([ip,target_ip])

        for ip in liste_ip:
            cursor.execute("""SELECT * FROM hosts WHERE ip = %s""", (ip,))
            rows = cursor.fetchall()
            for row in rows:
                mac = re.sub(r"[\s,]+", "|", row["mac"].strip())
                ip = re.sub(r"[\s,]+", "|", row["ip"].strip())
                hostname = re.sub(r"[\s,]+", "|", row["hostname"].strip())
                vendor = re.sub(r"[\s,]+", "|", row["vendor"].strip())
                OS = re.sub(r"[\s,]+", "|", row["OS"].strip())
                protocole = re.sub(r"[\s,]+", "|", row["protocole"].strip())
                data = row["data"]
                if ip not in already_add:
                    node.append({
                        "id": ip,
                        "title": hostname,
                        "subtitle": ip,
                        "mac": mac,
                        "vendor": vendor,
                        "OS": OS,
                        "protocole": protocole,
                        "color": "blue",
                        "highlighted": True,
                    })
                    already_add.append(ip)

                json_blobs = split_json_objects(data)
                for obj in json_blobs:
                    try:
                        entry = json.loads(obj)
                    except json.JSONDecodeError:
                        continue
                    if entry.get("PROTOCOL") == "ARP":
                        sender_ip = entry.get("SENDER_IP")
                        target_ip = entry.get("TARGET_IP")
                        if sender_ip != target_ip and target_ip not in liste_ip:
                            liste_ip2.append(target_ip)
                            edges.append([ip,target_ip])
            if len(rows) == 0:
                #on créer un node vide avec seulement l'IP
                if ip not in already_add:
                    node.append({
                        "id": ip,
                        "title": "?",
                        "subtitle": ip,
                        "mac": "?",
                        "vendor": "?",
                        "OS": "?",
                        "protocole": "?",
                        "color": "purple",
                        "highlighted": False,
                    })
                    already_add.append(ip)


        for ip in liste_ip2:
            cursor.execute("""SELECT * FROM hosts WHERE ip = %s""", (ip,))
            rows = cursor.fetchall()
            for row in rows:
                mac = re.sub(r"[\s,]+", "|", row["mac"].strip())
                ip = re.sub(r"[\s,]+", "|", row["ip"].strip())
                hostname = re.sub(r"[\s,]+", "|", row["hostname"].strip())
                vendor = re.sub(r"[\s,]+", "|", row["vendor"].strip())
                OS = re.sub(r"[\s,]+", "|", row["OS"].strip())
                protocole = re.sub(r"[\s,]+", "|", row["protocole"].strip())
                data = row["data"]
                if ip not in already_add:
                    node.append({
                        "id": ip,
                        "title": hostname,
                        "subtitle": ip,
                        "mac": mac,
                        "vendor": vendor,
                        "OS": OS,
                        "protocole": protocole,
                        "color": "blue",
                        "highlighted": True,
                    })
                    already_add.append(ip)
            if len(rows) == 0:
                #on créer un node vide avec seulement l'IP
                if ip not in already_add:
                    node.append({
                        "id": ip,
                        "title": "?",
                        "subtitle": ip,
                        "mac": "?",
                        "vendor": "?",
                        "OS": "?",
                        "protocole": "?",
                        "color": "purple",
                        "highlighted": False,
                    })
                    already_add.append(ip)


        cursor.close()
        conn.close()
        if(returnEdges):
            retour_edge = []
            for [a,b] in edges:
                retour_edge.append({
                    "id": str(uuid.uuid4()),
                    "source": a,
                    "target": b,
                    "thickness": 1,
                    "highlighted": False,
                    "color": "green"
                })
            return retour_edge
        return node 

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/graph/nodes", methods=['GET', 'OPTIONS'])
def graph_nodes():

    if request.method == 'OPTIONS':
        resp = make_response()
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
        resp.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
        return resp
    
    mac = request.args.get("mac")
    if not mac:
        return jsonify({"error": "Missing 'mac' parameter"}), 400


    csv_lines = [
        "id,title,subtitle,mac,vendor,OS,protocole,color,highlighted"
    ]
    nodes = generate_node(mac)
    for node in nodes:
        csv_lines.append(
            f'{node["id"]},{node["title"]},{node["subtitle"]},{node["mac"]},{node["vendor"]},{node["OS"]},{node["protocole"]},{node["color"]},{str(node["highlighted"]).lower()}'
        )
    return Response("\n".join(csv_lines), mimetype="text/csv")

@app.route("/graph/edges", methods=['GET', 'OPTIONS'])
def graph_edges():
    if request.method == 'OPTIONS':
        resp = make_response()
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
        resp.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
        return resp

    mac = request.args.get("mac")
    if not mac:
        return jsonify({"error": "Missing 'mac' parameter"}), 400
    csv_lines = [
        "id,source,target,thickness,highlighted,color"
    ]
    edges = generate_node(mac, True)
    for edge in edges:
        csv_lines.append(
            f'{edge["id"]},{edge["source"]},{edge["target"]},'
            f'{edge["thickness"]},{str(edge["highlighted"]).lower()},{edge["color"]}'
        )
    return Response("\n".join(csv_lines), mimetype="text/csv")



@app.route("/graph/visualization", methods=['GET'])
def graph_visualization():
    mac = request.args.get("mac")
    if not mac:
        return jsonify({"error": "Missing 'mac' parameter"}), 400
    
    # Générer le HTML complet avec le JavaScript intégré
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Visualisation du Réseau pour {mac}</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            overflow: hidden;
        }}
        #graph-container {{
            border: 1px solid #ccc;
            border-radius: 5px;
            padding: 10px;
            margin-top: 20px;
            width: 100%;
            height: 80vh;
        }}
        .node text {{
            font-size: 12px;
            pointer-events: none;
        }}
        .link {{
            stroke-opacity: 0.6;
        }}
        .loading {{
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100%;
            font-size: 18px;
            color: #666;
        }}
        .error {{
            color: red;
        }}
        .zoom-controls {{
            position: absolute;
            top: 80px;
            right: 30px;
            z-index: 1000;
        }}
        .zoom-btn {{
            display: block;
            width: 30px;
            height: 30px;
            margin-bottom: 5px;
            background: #fff;
            border: 1px solid #ccc;
            border-radius: 3px;
            cursor: pointer;
            text-align: center;
            line-height: 30px;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div id="graph-container">
        <div class="loading">Chargement des données réseau...</div>
    </div>
    <div class="zoom-controls">
        <button class="zoom-btn" id="zoom-in">+</button>
        <button class="zoom-btn" id="zoom-out">-</button>
        <button class="zoom-btn" id="zoom-reset">⟲</button>
    </div>

    <script>
        // URLs des endpoints API
        const nodesUrl = '/graph/nodes?mac={mac}';
        const edgesUrl = '/graph/edges?mac={mac}';
        
        // Fonction pour charger les données CSV et les convertir en JSON
        async function loadData(url) {{
            try {{
                const response = await fetch(url);
                if (!response.ok) {{
                    throw new Error(`HTTP error! status: ${{response.status}}`);
                }}
                const csvData = await response.text();
                
                // Convertir CSV en JSON
                const lines = csvData.split('\\n');
                if (lines.length < 2) return [];
                
                const headers = lines[0].split(',');
                const result = [];
                
                for (let i = 1; i < lines.length; i++) {{
                    if (!lines[i]) continue;
                    
                    const obj = {{}};
                    const currentline = lines[i].split(',');
                    
                    for (let j = 0; j < headers.length; j++) {{
                        obj[headers[j]] = currentline[j];
                    }}
                    result.push(obj);
                }}
                
                return result;
            }} catch (error) {{
                console.error('Error loading data:', error);
                document.getElementById('graph-container').innerHTML = 
                    '<p class="error">Erreur de chargement des données: ' + error.message + '</p>';
                return [];
            }}
        }}
        
        // Fonction principale pour afficher le graphe
        async function displayGraph() {{
            try {{
                // Charger les données des nœuds et des liens
                const [nodesData, edgesData] = await Promise.all([
                    loadData(nodesUrl),
                    loadData(edgesUrl)
                ]);
                
                if (nodesData.length === 0 || edgesData.length === 0) {{
                    document.getElementById('graph-container').innerHTML = 
                        '<p class="error">Aucune donnée valide à afficher</p>';
                    return;
                }}
                
                // Transformer les données pour D3.js
                const nodes = nodesData.map(node => ({{
                    id: node.id,
                    title: node.title,
                    subtitle: node.subtitle,
                    mac: node.mac,
                    vendor: node.vendor,
                    OS: node.OS,
                    protocole: node.protocole,
                    type: node.color === 'green' ? 'source' : 
                          node.color === 'blue' ? 'device' : 
                          node.color === 'purple' ? 'ip' : 'device',
                    color: node.color,
                    highlighted: node.highlighted === 'true'
                }}));
                
                // Créer un map des nodes pour accès rapide
                const nodeMap = new Map(nodes.map(node => [node.id, node]));
                
                const links = edgesData.map(edge => ({{
                    source: nodeMap.get(edge.source),
                    target: nodeMap.get(edge.target),
                    protocol: 'ARP',
                    count: parseInt(edge.thickness) || 1,
                    color: edge.color
                }}));


                

                // Nettoyer le conteneur
                const container = document.getElementById('graph-container');
                container.innerHTML = '';
                
                // Dimensions du graphe
                const width = container.clientWidth;
                const height = container.clientHeight;
                
                // Création du SVG avec zoom
                const svg = d3.select("#graph-container")
                    .append("svg")
                    .attr("width", width)
                    .attr("height", height)
                    .call(d3.zoom()
                        .scaleExtent([0.1, 8])
                        .on("zoom", zoomed));
                
                // Groupe pour le contenu zoomable
                const g = svg.append("g");
                
                // Simulation de forces
                const simulation = d3.forceSimulation(nodes)
                    .force("link", d3.forceLink(links).id(d => d.id).distance(100))
                    .force("charge", d3.forceManyBody().strength(-500))
                    .force("center", d3.forceCenter(width / 2, height / 2))
                    .force("collision", d3.forceCollide().radius(40));
                
                // Création des liens
                const link = g.append("g")
                    .selectAll("line")
                    .data(links)
                    .enter().append("line")
                    .attr("class", "link")
                    .attr("stroke", d => d.color || "#999")
                    .attr("stroke-width", d => Math.sqrt(d.count));
                
                // Ajout des étiquettes pour les liens
                const linkText = g.append("g")
                    .selectAll("text")
                    .data(links)
                    .enter().append("text")
                    .attr("font-size", 10)
                    .attr("fill", "#333")
                    .text(d => `ARP (${{d.count}}x)`);
                
                // Création des nœuds
                const node = g.append("g")
                    .selectAll("g")
                    .data(nodes)
                    .enter().append("g")
                    .call(d3.drag()
                        .on("start", dragstarted)
                        .on("drag", dragged)
                        .on("end", dragended));
                
                // Ajout des cercles pour les nœuds
                node.append("circle")
                    .attr("r", 10)
                    .attr("fill", d => {{
                        switch(d.type) {{
                            case "source": return "#e6550d";
                            case "device": return "#756bb1";
                            case "ip": return "#31a354";
                            default: return "#636363";
                        }}
                    }})
                    .attr("stroke", "#fff")
                    .attr("stroke-width", 2);
                
                // Ajout du texte pour les nœuds
                node.append("text")
                    .attr("dy", 20)
                    .attr("text-anchor", "middle")
                    .text(d => d.title === '?' ? d.subtitle : d.title)
                    .attr("font-size", 10)
                    .attr("fill", "#333");
                
                // Ajout d'info supplémentaire pour le nœud source
                node.filter(d => d.type === "source").append("text")
                    .attr("dy", 35)
                    .attr("text-anchor", "middle")
                    .text(d => {{
                        let info = [];
                        if (d.subtitle) info.push(d.subtitle);
                        if (d.OS && d.OS !== '?') info.push(d.OS);
                        return info.join(' - ');
                    }})
                    .attr("font-size", 9)
                    .attr("fill", "#666");
                
                // Mise à jour de la position
                simulation.on("tick", () => {{
                    link
                        .attr("x1", d => d.source.x)
                        .attr("y1", d => d.source.y)
                        .attr("x2", d => d.target.x)
                        .attr("y2", d => d.target.y);
                    
                    linkText
                        .attr("x", d => (d.source.x + d.target.x) / 2)
                        .attr("y", d => (d.source.y + d.target.y) / 2);
                    
                    node
                        .attr("transform", d => `translate(${{d.x}},${{d.y}})`);
                }});
                
                // Fonctions pour le drag and drop
                function dragstarted(event, d) {{
                    if (!event.active) simulation.alphaTarget(0.3).restart();
                    d.fx = d.x;
                    d.fy = d.y;
                }}
                
                function dragged(event, d) {{
                    d.fx = event.x;
                    d.fy = event.y;
                }}
                
                function dragended(event, d) {{
                    if (!event.active) simulation.alphaTarget(0);
                    d.fx = null;
                    d.fy = null;
                }}
                
                // Fonction de zoom
                function zoomed(event) {{
                    g.attr("transform", event.transform);
                }}
                
                // Contrôles de zoom
                document.getElementById('zoom-in').addEventListener('click', () => {{
                    svg.transition().call(svg.zoom.scaleBy, 1.2);
                }});
                
                document.getElementById('zoom-out').addEventListener('click', () => {{
                    svg.transition().call(svg.zoom.scaleBy, 0.8);
                }});
                
                document.getElementById('zoom-reset').addEventListener('click', () => {{
                    svg.transition().call(svg.zoom.transform, d3.zoomIdentity);
                }});
                
                // Légende
                const legend = svg.append("g")
                    .attr("transform", `translate(20, ${{height - 120}})`);
                
                const legendData = [
                    {{ color: "#e6550d", text: "Appareil source" }},
                    {{ color: "#756bb1", text: "Appareil réseau" }},
                    {{ color: "#31a354", text: "Adresse IP" }},
                    {{ color: "green", text: "Connexion ARP" }}
                ];
                
              


                legend.selectAll("legend-items")
                    .data(legendData)
                    .enter().append("g")
                    .attr("transform", (d, i) => `translate(0, ${{i * 20}})`)
                    .each(function(d) {{
                        d3.select(this).append("circle")
                            .attr("r", 6)
                            .attr("cx", 10)
                            .attr("cy", 0)
                            .attr("fill", d.color);
                        
                        d3.select(this).append("text")
                            .attr("x", 25)
                            .attr("y", 4)
                            .attr("font-size", 10)
                            .text(d.text);
                    }});
            }} catch (error) {{
                console.error("Erreur lors de l'affichage du graphe:", error);
                document.getElementById('graph-container').innerHTML = 
                    '<p class="error">Une erreur est survenue lors du chargement du graphe: ' + error.message + '</p>';
            }}
        }}
        
        // Démarrer le chargement et l'affichage du graphe
        displayGraph();
    </script>
</body>
</html>
    """
    
    return Response(html_content, mimetype="text/html")

@app.route("/")
def index():
    return "Welcome to the active API!"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)