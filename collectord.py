#!/usr/bin/env python
 
import time
import logging
import socket
import SocketServer
import collectornetflow 
import collectorsyslog 
from threading import Thread, Lock
import collector_config #import parse_args, parse_config, print_args_config, configfile, logfile, be_verbose, is_daemon
import correlator

args = collector_config.parse_args()
config = collector_config.parse_config(collector_config.configfile)
if config == None :
        print('Error parsing args or config file')
        quit()

if collector_config.be_verbose :
    collector_config.print_args_config(config)

configured_threads = []
configured_sockets = []
 
logging.basicConfig(level=logging.INFO, format='%(message)s', datefmt='', filename=collector_config.logfile, filemode='a')
 
try:
    for s in config['sections']:
        if config[s]['type']=='syslog' :
            handler = collectorsyslog.CollectorSyslogHandler
        elif config[s]['type']=='netflow9' :
            handler = collectornetflow.CollectorNetflowHandler
        elif config[s]['type']=='netflow5' :
            handler = None # Need to fix that
        elif config[s]['type']=='ipfix' :
            handler = None # Need to fix that
        else :
            print("Unknown collector type {0}".format(config[s]['type']))
            quit()
        ss = SocketServer.UDPServer((config[s]['address'], int(config[s]['port'])), handler)
        configured_sockets.append(ss)
        t = Thread(target=ss.serve_forever, name="{0} listener".format(s))
        configured_threads.append(t)


    """
    serv_syslog = SocketServer.UDPServer((HOST,PORT_SYSLOG), collectorsyslog.CollectorSyslogHandler)
    serv_netflow = SocketServer.UDPServer((HOST, PORT_NETFLOW), collectornetflow.CollectorNetflowHandler)
    configured_sockets.append(serv_syslog)
    configured_sockets.append(serv_netflow)

    t_syslog = Thread(target=serv_syslog.serve_forever, name="Syslog listener")
    t_netflow = Thread(target=serv_netflow.serve_forever, name="Netflow listener") #(poll_interval=0.5)
    configured_threads.append(t_syslog)
    configured_threads.append(t_netflow)
    t_netflow_flush = Thread(target=collectornetflow.flushNetflow, name="Netflow Flusher")
    t_syslog_flush = Thread(target=collectorsyslog.flushSyslog, name="Syslog Flusher")
    configured_threads.append(t_netflow_flush)
    configured_threads.append(t_syslog_flush)
    """
    t = Thread(target=correlator.correlator, name="Correlator Flusher")
    configured_threads.append(t)

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
    correlator.do_correlation = False
    quit() 

