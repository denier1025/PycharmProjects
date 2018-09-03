#!/usr/bin/env python

import requests

def download(url):
    response = requests.get(url)
    file_name = url.split("/")[-1]
    with open(file_name, "wb") as out_file:
        out_file.write(response.content)

download("https://cdn.motor1.com/images/mgl/KE0Aq/s1/2018-nissan-gt-r.jpg")