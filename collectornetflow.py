#!/usr/bin/env python

import sys
import os
import time
from datetime import datetime, timedelta
import SocketServer
import ipfix.v9pdu
import ipfix.ie
from threading import Thread, Lock

ipfix.ie.use_iana_default()
ipfix.ie.use_5103_default()

netflows = []
netflows_lock = Lock()
debug_log = open("netflow.log", "w+")
debug_log.write("Log started at {0}\n{1}\n".format(datetime.now(), '-'*150))

msgcount = 0
do_flush = True
templates = {}
accepted_tids = set()
def dummy1(o,b) : pass

"""
TODO: flush all unsaved messages when exit thread
"""
def flushNetflow() :
    while do_flush :
        netflows_lock.acquire()
        for flow in netflows :
            flush_time = datetime.now()
            if flush_time - flow['recieved_at'] < timedelta(seconds=15) : continue # flush only records, that are 15 seconds old
            debug_log.write("Flow recieved from {0} at {1}\n".format(flow['source'], flow['recieved_at']))
            debug_log.write("Flow recieved from {0} at {1}\n".format(flow['source'], flow['recieved_at']))
            for key in flow['rec']:
                 debug_log.write("  {0:30} => {1}\n".format(key, str(flow['rec'][key])))
            debug_log.write("{0}\n".format('-'*150))
            netflows.remove(flow)
        netflows_lock.release()
        os.fsync(debug_log.fileno())
        time.sleep(1) # Sleep for 5 seconds
    print("netflows len {0}".format(len(netflows)))

class CollectorNetflowHandler(SocketServer.DatagramRequestHandler):
    
    def handle(self):
        global msgcount, netflows
        msgcount = msgcount + 1
        reccount = 0
        now = datetime.now()
        
        #debug_log.write("NETFLOW: connection from {0}\n".format(str(self.client_address)))
        print("NETFLOW: connection from {0}".format(str(self.client_address)))
        r = ipfix.v9pdu.from_stream(self.rfile)
        try:
            r.templates = templates[str(self.client_address)]
        except KeyError as e:
            templates[str(self.client_address)] = {}
            r.templates = templates[str(self.client_address)]

        r.accepted_tids = accepted_tids
        r.unknown_data_set_hook = dummy1

        for rec in r.namedict_iterator():
            record = {}
            record['odid'] = now
            record['recieved_at'] = now
            record['timestamp'] = datetime.fromtimestamp(rec.export_epoch)
            record['source'] = str(self.client_address)
            record['rec'] = rec
            netflows_lock.acquire()
            netflows.append(record)
            netflows_lock.release()
            #debug_log.write("--- record {0} in message {1} from {2}---\n".format(reccount, msgcount, str(self.client_address)))
            reccount += 1
            #for key in rec:
            #     debug_log.write("  {0:30} => {1}\n".format(key, str(rec[key])))
        #debug_log.write("reccount = {0}\n".format(str(reccount)))
        debug_log.write("{0}\n".format('-'*150))
    
    
def find_flow(src_ip,src_port,dst_ip,dst_port,ts) : 
    result = []
    netflows_lock.acquire()
    for flow in netflows :
        prob = 0 # probability
        if abs(flow['timestamp']-ts) > timedelta(seconds=3) : # 6 seconds interval
            continue
        if src_ip != None and 'sourceIPv4Address' in flow:
            if src_ip == flow['sourceIPv4Address'] :
                prob += 1
        if src_port != None and 'sourceTransportPort' in flow:
            if src_port == flow['sourceTransportPort'] :
                prob += 1
        if dst_ip != None and 'destinationIPv4Address' in flow:
            if dst_ip == flow['destinationIPv4Address'] :
                prob += 1
        if dst_port != None and 'destinationTransportPort' in flow:
            if dst_port == flow['destinationTransportPort'] :
                prob += 1
        if prob > 2 :
            result.append(flow)
    netflows_lock.release()
    if len(result) == 0 : return None
    else : return result
    
def print_flow(f) :
    return "PROTO: {0}, {1}:{2}->{3}:{4}".format(f['protocolIdentifier'],f['sourceIPv4Address'],f['sourceTransportPort'],f['destinationIPv4Address'],f['destinationTransportPort'])


if __name__ == "__main__":
    ss = SocketsSrver.UDPServer(("", 9995), CollectorNetflowHandler)
    ss.serve_forever()
