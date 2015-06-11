#!/usr/bin/env python

import sys
import os
import time
from datetime import datetime, timedelta
import SocketServer
import ipfix.v9pdu
import ipfix.v5pdu
import ipfix.ie
import ipfix.template
from threading import Thread, Lock
import Queue
from correlator import netflowQueue
import collector_config 

ipfix.ie.use_iana_default()
ipfix.ie.use_5103_default()

msgcount = 0
do_flush = True
templates = {}
accepted_tids = set()
def dummy1(o,b) : pass

class CollectorNetflow9Handler(SocketServer.DatagramRequestHandler):
    
    def handle(self):
        global msgcount, netflows
        msgcount = msgcount + 1
        reccount = 0
        now = datetime.now()
        
        #debug_log.write("NETFLOW: connection from {0}\n".format(str(self.client_address)))
        if collector_config.be_verbose : print("NETFLOW: connection from {0}".format(str(self.client_address)))
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
            record['type'] = 'netflow9'
            record['odid'] = now # FIXME: This wrong
            record['recieved_at'] = now
            record['timestamp'] = datetime.fromtimestamp(r.export_epoch)
            record['source'] = str(self.client_address)
            record['rec'] = rec
            netflowQueue.put(record)
            reccount += 1
    
    
class CollectorNetflow5Handler(SocketServer.DatagramRequestHandler):
    
    def handle(self):
        global msgcount, netflows
        msgcount = msgcount + 1
        reccount = 0
        now = datetime.now()
        
        if collector_config.be_verbose : print("NETFLOW: connection from {0}".format(str(self.client_address)))
        r = ipfix.v5pdu.from_stream(self.rfile)

        for rec in r.namedict_iterator():
            record = {}
            record['type'] = 'netflow5'
            record['odid'] = now # FIXME: This wrong
            record['recieved_at'] = now
            record['timestamp'] = datetime.fromtimestamp(r.export_epoch)
            record['source'] = str(self.client_address)
            record['rec'] = rec
            netflowQueue.put(record)
            reccount += 1
    
    
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
