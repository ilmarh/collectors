#!/usr/bin/env python3.4

import os
import sys
import json
import SocketServer
import socket
import time
from datetime import datetime, timedelta
from logsparser.lognormalizer import LogNormalizer as LN
from threading import Thread, Lock
from collectornetflow import find_flow, print_flow
import collector_config 
import Queue
from correlator import syslogQueue

messages = []
messages_lock = Lock()

debug_log = open("syslog.log", "w+")
debug_log.write("Log started at {0}\n{1}\n".format(datetime.now(), '-'*150))

do_flush = True

normalizer = LN('/usr/local/share/logsparser/normalizers')

"""
TODO: flush all unsaved messages when exit thread
def flushSyslog() :
    while do_flush :
        messages_lock.acquire()
        for msg in messages :
            
            log = msg['msg']
            if msg['flow'] == None :
                a = None
                b = None
                c = None
                d = None
                if 'source_ip' in log: a = log['source_ip']
                if 'source_port' in log: b = log['source_port']
                if 'dest_ip' in log: c = log['dest_ip']
                if 'dest_port' in log: d = log['dest_port']
                msg['flow'] = find_flow(a,b,c,d,log['date'])

            flush_time = datetime.now()
            if flush_time - msg['recieved_at'] < timedelta(seconds=15) : continue # flush only records, that are 15 seconds old

            debug_log.write("Message from {0} at {1}\n".format(msg['source'], msg['recieved_at']))
            for key in log.keys() :
                if key != 'raw' :
                    debug_log.write("{0} => {1}\n".format(key, str(log[key])))
            if len(log.keys()) < 2 :
                debug_log.write("{0} => {1}\n".format(log.keys()[0], str(log[key])))
                debug_log.write("tags => parsefailure")
            else :
                debug_log.write("raw => {0}\n".format(str(log['raw'])))
            if msg['flow'] != None :
                debug_log.write("associated flow => {0}\n".format(print_flow(msg['flow'])))
            debug_log.write("{0}\n".format('-'*150))
            messages.remove(msg)
        messages_lock.release()
        os.fsync(debug_log.fileno())
        time.sleep(1) # Sleep for 5 seconds
    print("messages len {0}".format(len(messages)))
"""

def _parse_logdata(l, t='syslog', p=None) :
     log = {}
     if p :
         log = {'raw' : l[:],
                'program': p,
                'body': l[:] } # a LogNormalizer expects input as a dictionary, grab log line, remove the trailing \n
     else :
         log = {'raw' : l[:],
                'logtype' : t } # a LogNormalizer expects input as a dictionary, grab log line, remove the trailing \n
     try :
         normalizer.normalize(log)
     except :
         print(sys.exc_info())
         if 'tags' in log.keys() :
             log['tags'] = log['tags'] + ', parsefailure'
         else :
             log['tags'] = 'parsefailure'
     return log


class CollectorSyslogHandler(SocketServer.DatagramRequestHandler):
    
    def handle(self):

        now = datetime.now()
        #debug_log.write("SYSLOG connection from {0}\n".format(str(self.client_address)))
        if collector_config.be_verbose : print("SYSLOG connection from {0}".format(str(self.client_address)))
        data = bytes.decode(self.request[0].strip())
        #socket = self.request[1]
        l = str(data)
        #debug_log.write("{0} : {1}\n".format(self.client_address[0], l))
        log = _parse_logdata(l)
        #log = _parse_logdata(l, p="mikrotik")

        try :
            log["dest_ip"] = socket.gethostbyname_ex(log["source"])
        except :
            #log["dest_host_ex"] = "{0} log source".format(log["source"])
            log["dest_ip"] = "{0} log source".format(self.client_address[0])

        msg = {}
        msg['recieved_at'] = now
        msg['source'] = str(self.client_address)
        msg['msg'] = log
        msg['flow'] = None
        #messages_lock.acquire()
        syslogQueue.put(msg)
        #messages_lock.release()


#	logging.info(str(data))

if __name__ == "__main__":


 if len(sys.argv) != 2 :
    print('{0} used to parse provided logfile. have some twerks to handle standard syslog and web-server formats'.format(sys.argv[0]))
    print("Need to give log file name to parse")
    quit()

 if os.path.isfile(sys.argv[1]): log_path = sys.argv[1]

  #print(normalizer.dtd.error_log.filter_from_errors()[0])
 for l in open(log_path, 'r') :
     print('-'*25)
#    print logline[:-1] # grab log line, remove the trailing \n
     if l[0:3] == "May" or l[0] == '<':
         log = _parse_logdate(l)
     else :
         log = _parse_logdate(l, p='nginx')

     for key in log.keys() :
        if key != 'raw' :
            print(key + " => " + str(log[key]))
     if len(log.keys()) < 2 :
        print(log.keys()[0] + " => " + str(log[key]))
        print("tags => parsefailure")
     else :
        print("raw => " + str(log['raw']))
#     print log
