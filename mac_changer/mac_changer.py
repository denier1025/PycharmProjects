#!/usr/bin/env python

import subprocess
import argparse
import re
import scapy.all as scapy

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
