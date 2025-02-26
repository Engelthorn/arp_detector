#!/usr/bin/python3.12
from scapy.all import sniff

ip_mac_dict = {}


def process_packet_callback(packet):
    print("\n\n-------------------------------------------------------------------------------"
          "\n[!] ARP Detector is now running..."
          "\nPress CTRL + C to stop\n")

    ip_src = packet['ARP'].psrc
    mac_src = packet['Ether'].src
    if mac_src in ip_mac_dict.keys():
        if ip_mac_dict[mac_src] != ip_src:
            try:
                old_ip = ip_mac_dict[mac_src]
            except:
                old_ip = "unknown"
            alert_msg = (f"\n\tPossible ARP attack detected!"
                         f"\n\tMaybe the machine with IP {str(old_ip)} is pretending to be {str(ip_src)}."
                         f"\n-------------------------------------------------------------------------------\n")
            return alert_msg
        else:
            ip_mac_dict[mac_src] = ip_src


sniff(count=0, filter="arp", store=0, prn=process_packet_callback)
