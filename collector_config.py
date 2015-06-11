#!/usr/bin/env python

import os
import argparse
import ConfigParser

configfile = None
logfile = None
is_daemon = False
be_verbose = False

def parse_args() :
    
    global configfile, logfile, is_daemon, be_verbose
    ap = argparse.ArgumentParser(description="Collector and correlator of Netflow v5, v9 and IPFIX flows and Syslog messages")
    ap.add_argument('-c', metavar='configfile', default='/usr/local/etc/collectord.conf', help="collectors' config file")
    ap.add_argument('-l', metavar='logfile', default='/var/log/collectord.log', help='log file for collector own messages')
    ap.add_argument('-d', action='store_true', help='start as daemon')
    ap.add_argument('-v', action='store_true', help='verbose debug messages')
    args = ap.parse_args()

    configfile = args.c
    logfile = args.l
    is_daemon = args.d
    be_verbose = args.v
    return args

def parse_config(filename) :
    if not os.path.isfile(filename):
        print("File {0} not found".format(filename))
        quit()

    cf = ConfigParser.SafeConfigParser()
    cf.read(filename)
    res = {}
    res['sections'] = cf.sections()
    for sect in res['sections'] :
        opts = {}
        for opt in ['address', 'port', 'type'] :
            opts[opt] = cf.get(sect, opt)
        res[sect] = opts
    return res

def print_args_config(config) :

    print("Running the following config:")
    print("    logfile name: {0}".format(logfile))
    print("    config file name: {0}".format(configfile))
    print("    is daemon: {0}".format(is_daemon))
    print("    be verbose: {0}".format(be_verbose))
    print('Config file is:')
    for s in config['sections']:
        print("Section {0}:".format(s))
        print("    Collector type: {0}".format(config[s]['type']))
        print("    Listening on  : {0}:{1}".format(config[s]['address'], config[s]['port']))

if __name__ == "__main__":
    parse_args()
    c = parse_config(configfile)
    if c == None :
        print('Error parsing config file')
    else :
        print_args_config(c)
               
