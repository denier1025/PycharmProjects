#!/usr/bin/env python

import subprocess
import re
import scapy.all as scapy

def get_cidr():
    result = subprocess.check_output(["ip", "route"])
    cidr = re.search(r"([1-9]|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])(\.(\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])){3}\/\d+", str(result))
    return cidr.group(0)

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        clients_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(clients_dict)
    return clients_list

def print_result(results_list):
    print("IP\t\tMAC-address\n---------------------------------")
    for element in results_list:
        print(element["ip"] + "\t" + element["mac"])

# cidr_result = get_cidr()
scan_result = scan("192.168.0.1/24")
print_result(scan_result)
