#!/usr/bin/env python

import connector, sys

try:
    tcp_socket_connector = connector.Connector("31.28.252.133", 49099)
    tcp_socket_connector.run()
except Exception:
    sys.exit()

# SystemExit do not catch
# Run main connection through second thread
# and check connection by main thread every 5 min,
# if connection is lost - interrupt the second thread and run it again
