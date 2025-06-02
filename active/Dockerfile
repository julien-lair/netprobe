FROM python:3.10-slim

RUN apt update && apt install -y \
    avahi-utils \
    avahi-daemon \
    dbus \
    procps \
    iputils-arping \
    snmp \
    nmap \
 && apt clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN rm -f /run/dbus/pid

COPY entrypoint.sh /entrypoint.sh
COPY snmp.sh /snmp.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
