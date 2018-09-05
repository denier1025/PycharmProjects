#!/usr/bin/env python

import connector

tcp_socket_connector = connector.Connector("31.28.252.133", 49099)
tcp_socket_connector.run()
