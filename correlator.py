#!/usr/bin/env python
import Queue
from threading import Thread
from datetime import datetime, timedelta
import time
import os
import sys
import collector_config

do_correlation = True

netflowQueue = Queue.Queue()
flushnetflowQueue = Queue.Queue()
syslogQueue = Queue.Queue()
flushsyslogQueue = Queue.Queue()

ndebug_log = open("netflow.log", "w+")
ndebug_log.write("Log started at {0}\n{1}\n".format(datetime.now(), '-'*150))

sdebug_log = open("syslog.log", "w+")
sdebug_log.write("Log started at {0}\n{1}\n".format(datetime.now(), '-'*150))

netflows = []
messages = []

def flushNetflow() :
    while not flushnetflowQueue.empty() : # What if queue will always be not empty?
        flow = flushnetflowQueue.get()
        ndebug_log.write("Flow recieved from {0} at {1}\n".format(flow['source'], flow['recieved_at']))
        #ndebug_log.write("Rec entry: {0}\n".format(flow['rec']))
        for key in flow['rec']:
             ndebug_log.write("  {0:30} => {1}\n".format(key, str(flow['rec'][key])))
        ndebug_log.write("{0}\n".format('-'*150))
        flushnetflowQueue.task_done()
    os.fsync(ndebug_log.fileno())


def flushSyslog() :
    while not flushsyslogQueue.empty() : # What if queue will always be not empty?
        msg = flushsyslogQueue.get()
        log = msg['msg']
        
        sdebug_log.write("Message from {0} at {1}\n".format(msg['source'], msg['recieved_at']))
        for key in log.keys() :
            if key != 'raw' :
                sdebug_log.write("{0} => {1}\n".format(key, str(log[key])))
        if len(log.keys()) < 2 :
            sdebug_log.write("{0} => {1}\n".format(log.keys()[0], str(log[key])))
            sdebug_log.write("tags => parsefailure")
        else :
            sdebug_log.write("raw => {0}\n".format(str(log['raw'])))
        if msg['flow'] != None :
            sdebug_log.write("associated flow => {0}\n".format(print_flow(msg['flow'])))
        sdebug_log.write("{0}\n".format('-'*150))
        flushsyslogQueue.task_done()
    os.fsync(sdebug_log.fileno())

def correlator() :
    nf_dump_t = Thread(target=flushNetflow, name="Netflow flusher")
    sl_dump_t = Thread(target=flushSyslog, name="Syslog flusher")
    while do_correlation :
        # Get netflow and syslog from collectors
        while not netflowQueue.empty() : # What if queue will always be not empty?
            flow = netflowQueue.get()
            netflows.append(flow)
            netflowQueue.task_done()
        while not syslogQueue.empty() : # What if queue will always be not empty?
            msg = syslogQueue.get()
            messages.append(msg)
            syslogQueue.task_done()
        
        for flow in netflows :
            flush_time = datetime.now()
            if flush_time - flow['recieved_at'] > timedelta(seconds=15) : # flush only records, that are 15 seconds old
                flushnetflowQueue.put(flow)
                netflows.remove(flow)

        for msg in messages :
            flush_time = datetime.now()
            if flush_time - msg['recieved_at'] > timedelta(seconds=15) :  # flush only records, that are 15 seconds old
                flushsyslogQueue.put(msg)
                messages.remove(msg)

        if not nf_dump_t.isAlive() :
            nf_dump_t = Thread(target=flushNetflow, name="Netflow flusher")
            nf_dump_t.start()
        if not sl_dump_t.isAlive() :
            sl_dump_t = Thread(target=flushSyslog, name="Syslog flusher")
            sl_dump_t.start()

    if collector_config.be_verbose : print("Flushing remaining netflows{0}, syslog messages {1} and exit".format(len(netflows), len(messages)))
    for flow in netflows : flushnetflowQueue.put(flow)
    for msg in messages : flushsyslogQueue.put(msg)
    if not nf_dump_t.isAlive() : flushNetflow() # direct flush call
    else : nf_dump_t.join() # else just join and block on thread
    if not sl_dump_t.isAlive() : flushSyslog()
    else : sl_dump_t.join()
    
