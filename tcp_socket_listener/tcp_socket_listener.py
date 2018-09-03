#!/usr/bin/env python

import listener

tcp_socket_listener = listener.Listener("192.168.0.100", 4444)
tcp_socket_listener.run()
