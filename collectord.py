#!/usr/bin/env python
 
## Tiny Syslog Server in Python.
##
## This is a tiny syslog server that is able to receive UDP based syslog
## entries on a specified port and save them to a file.
## That's it... it does nothing else...
## There are a few configuration parameters.
 
LOG_FILE = 'youlogfile.log'
HOST, PORT_SYSLOG, PORT_NETFLOW = "0.0.0.0", 515, 9995
 
#
# NO USER SERVICEABLE PARTS BELOW HERE...
#
import time
import logging
import socket
import SocketServer
import collectornetflow 
import collectorsyslog 
from threading import Thread, Lock
 
logging.basicConfig(level=logging.INFO, format='%(message)s', datefmt='', filename=LOG_FILE, filemode='a')
 
configured_threads = []
configured_sockets = []

if __name__ == "__main__":
    try:
        serv_syslog = SocketServer.UDPServer((HOST,PORT_SYSLOG), collectorsyslog.CollectorSyslogHandler)
        serv_netflow = SocketServer.UDPServer((HOST, PORT_NETFLOW), collectornetflow.CollectorNetflowHandler)
        configured_sockets.append(serv_syslog)
        configured_sockets.append(serv_netflow)

        t_syslog = Thread(target=serv_syslog.serve_forever, name="Syslog listener")
        t_netflow = Thread(target=serv_netflow.serve_forever, name="Netflow listener") #(poll_interval=0.5)
        t_netflow_flush = Thread(target=collectornetflow.flushNetflow, name="Netflow Flusher")
        t_syslog_flush = Thread(target=collectorsyslog.flushSyslog, name="Syslog Flusher")
        configured_threads.append(t_syslog)
        configured_threads.append(t_netflow)
        configured_threads.append(t_netflow_flush)
        configured_threads.append(t_syslog_flush)

        for t in configured_threads :
            t.start()

        #for t in configured_threads :
         #   t.join()

        while True : 
            time.sleep(10)
            for t in configured_threads :
                print("{0} is alive {1}".format(t.name, t.isAlive()))

    except (IOError, SystemExit):
        raise
    except KeyboardInterrupt:
        print("Crtl+C Pressed. Shutting down.")
        for s in configured_sockets :
            s.shutdown()
        collectorsyslog.do_flush = False
        collectornetflow.do_flush = False
        quit() 

