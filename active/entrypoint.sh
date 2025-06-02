#!/bin/bash

set -e

# Démarrer D-Bus
mkdir -p /var/run/dbus
dbus-daemon --system --fork

# Attendre que D-Bus soit prêt (optionnel mais utile)
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
