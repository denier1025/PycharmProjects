#!/usr/bin/env python

import socket, listener


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = ""
    try:
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
    except:
        ip = "127.0.0.1"
    finally:
        s.close()
        return ip

tcp_socket_listener = listener.Listener(get_ip(), 49099)
tcp_socket_listener.run()
