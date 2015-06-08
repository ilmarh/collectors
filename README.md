# collectors
Netflow v5, v9, IPFIX and Syslog collector and correlator on Python 2.7+

This service is using Python IPFIX library 
(https://github.com/britram/python-ipfix) backported to 2.7 and Syslog parser
and normalizer library pylogsparcer (https://github.com/wallix/pylogsparser).

Netflow v5 is not supported yet.

To run collector, set HOST, PORT_SYSLOG and PORT_NETFLOW vars and enter
something like python collectord.py on the command prompt

Right now it just saves captured messages and flows to netflow.log and 
syslog.log files
