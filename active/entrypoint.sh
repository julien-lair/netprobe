#!/bin/bash
set -e

# Nettoyer les PID orphelins
[ -f /run/dbus/pid ] && ! pgrep -x "dbus-daemon" > /dev/null && rm -f /run/dbus/pid
[ -f /run/avahi-daemon/pid ] && ! pgrep -x "avahi-daemon" > /dev/null && rm -f /run/avahi-daemon/pid

# Préparer les répertoires
mkdir -p /run/dbus /run/avahi-daemon

# Lancer dbus-daemon
echo "Lancement de dbus-daemon..."
dbus-daemon --system &

# Attendre que D-Bus soit prêt
sleep 1

# Vérifier si avahi-daemon est déjà en cours (à cause du mode host)
if pgrep -x "avahi-daemon" > /dev/null; then
    echo "avahi-daemon déjà en cours, on ne relance pas."
else
    echo "Lancement de avahi-daemon..."
    avahi-daemon --daemonize --no-chroot
fi

# Lancer l’application
echo "Lancement de l’application Python..."
exec python main.py
