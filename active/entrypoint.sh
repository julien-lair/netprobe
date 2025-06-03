#!/bin/bash

set -e

# Nettoyer le fichier de PID D-Bus s’il est orphelin
if [ -f /run/dbus/pid ] && ! pgrep -x "dbus-daemon" > /dev/null; then
    echo "Fichier PID D-Bus présent sans processus, suppression..."
    rm -f /run/dbus/pid
fi

# Démarrer D-Bus
mkdir -p /var/run/dbus
dbus-daemon --system --fork

# Attendre que D-Bus soit prêt
sleep 1

# Démarrer Avahi
avahi-daemon --daemonize --no-chroot

# Vérifier si avahi-daemon a bien démarré
if ! pgrep -x "avahi-daemon" > /dev/null; then
    echo "Erreur : avahi-daemon n’a pas démarré."
    exit 1
fi

# Lancer ton app
exec python main.py
