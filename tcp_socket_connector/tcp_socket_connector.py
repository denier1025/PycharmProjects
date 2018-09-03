#!/usr/bin/env python

import connector

tcp_socket_connector = connector.Connector("192.168.0.100", 4444)
tcp_socket_connector.run()
