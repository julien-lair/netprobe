#!/bin/bash

oid="1.3.6.1.2.1.1"
timeout_seconds=1
max_parallel=20
scan_ip() {
    ip="$1"
    community="$2"
    output=$(timeout "$timeout_seconds" snmpwalk -v2c -c "$community" "$ip" "$oid" 2>/dev/null)
    #echo "commande : snmpwalk -v2c -c $community $ip $oid"
    if [[ $? -eq 0 && -n "$output" ]]; then
        echo -e "[✅] $ip\n$output\n--------------------------------------"
    else
        echo "[❌] $ip Pas de réponse"
    fi
}

generate_ips() {
    input="$1"

    # IP unique simple (ex: 10.105.0.88)
    if [[ "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "$input"
        return
    fi

    # /24 CIDR (ex: 10.105.0.0/24)
    if [[ "$input" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.0/24$ ]]; then
        o1="${BASH_REMATCH[1]}"
        o2="${BASH_REMATCH[2]}"
        o3="${BASH_REMATCH[3]}"
        for i in {1..254}; do
            echo "$o1.$o2.$o3.$i"
        done
        return
    fi

    # /16 CIDR (ex: 10.105.0.0/16)
    if [[ "$input" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.0\.0/16$ ]]; then
        o1="${BASH_REMATCH[1]}"
        o2="${BASH_REMATCH[2]}"
        for o3 in {0..255}; do
            for o4 in {1..254}; do
                echo "$o1.$o2.$o3.$o4"
            done
        done
        return
    fi

    echo "Format d'entrée non supporté: $input" >&2
    exit 1
}

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <IP|CIDR (/24 ou /16)>"
    exit 1
fi

input=$1
community=$2
active_jobs=0
pids=()

echo "🔎 Scan SNMP actif sur $input ..."

for ip in $(generate_ips "$input"); do
    scan_ip "$ip" "$community" &

    pids+=($!)
    ((active_jobs++))

    if [[ $active_jobs -ge $max_parallel ]]; then
        wait "${pids[0]}"
        unset 'pids[0]'
        pids=("${pids[@]}")  # reindexe le tableau
        ((active_jobs--))
    fi
done

# attendre la fin des derniers jobs
for pid in "${pids[@]}"; do
    wait "$pid"
done

