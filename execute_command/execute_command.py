#!/usr/bin/env python

import subprocess

command = "msg * You are under attack!"
subprocess.Popen(command, shell=True)
