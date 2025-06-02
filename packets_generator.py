#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import UDP, IP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS, DNSQR, DNSRR

# Configure interface to send packets, update to your own interface
iface = "enp2s0"  # Replace with your actual network interface

def is_broadcast_or_multicast(packet):
    """Check if the packet is broadcast or multicast."""
    if Ether in packet:
        dst_mac = packet[Ether].dst
        # Broadcast
        if dst_mac == "ff:ff:ff:ff:ff:ff":
            return True
        # IPv4 Multicast (01:00:5e)
        if dst_mac.startswith("01:00:5e"):
            return True
        # IPv6 Multicast (33:33)
        if dst_mac.startswith("33:33"):
            return True
        # Other Multicast Ranges
        # Example: Link Layer Discovery Protocol (LLDP)
        if dst_mac.startswith("01:80:c2"):
            return True
        # Cisco Discovery Protocol (CDP)
        if dst_mac in ["01:00:0c:cc:cc:cc"]:
            return True
        # Precision Time Protocol (PTP)
        if dst_mac in ["01:1b:19:00:00:00"]:
            return True
    return False

def send_pcap_file(pcap_file):
    """Send a PCAP file using Scapy."""
    packets = rdpcap(pcap_file)  # Read PCAP file
    broadcast_multicast_packets = [pkt for pkt in packets if is_broadcast_or_multicast(pkt)]
    sendp(broadcast_multicast_packets, iface=iface, verbose=1)  # Send packets


### Main Sequence

if __name__ == "__main__":
    # Simulate DHCP transaction
    #client_mac = send_dhcp_discover()  # Client sends DHCP Discover
    #send_dhcp_request(client_mac)      # Client sends DHCP Request

    #send_pcap_file("pcaps/DHCP/DHCP.pcap")  # Send a PCAP file with DHCP transaction
    #send_pcap_file("pcaps/ARP/arp.pcap")  # Send a PCAP file with DHCP transaction
    #send_pcap_file("pcaps/SP/SP.pcapng")  # Send a PCAP file with SP protocol
    send_pcap_file("pcaps/SSDP/SSDP.pcapng")  # Send a PCAP file with SSDP protocol
    send_pcap_file("pcaps/LLDP/LLDP.pcap")  # Send a PCAP file with LLDP protocol
    send_pcap_file("pcaps/CDP/cdp.pcap")  # Send a PCAP file with CDP protocol
    send_pcap_file("pcaps/CDP/cdp_v2.pcap")  # Send a PCAP file with CDP protocol
    #send_pcap_file("pcaps/WOL/wol.pcap")  # Send a PCAP file with WOL protocol
    #send_pcap_file("pcaps/big.pcapng")  # Send a PCAP file with WOL protocol
