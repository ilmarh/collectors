# collectors
Netflow v5, v9, IPFIX and Syslog collector and correlator on Python 2.7+

This service is using Python IPFIX library 
(https://github.com/britram/python-ipfix) backported to 2.7 and Syslog parser
and normalizer library pylogsparcer (https://github.com/wallix/pylogsparser).

To run collector, edit collectord.conf file to suit our needs and run
something like python collectord.py on the command prompt, passing the
following comandline arguments:
  -c <filename> -- config file name with path
                   (default is /usr/local/etc/collectd.conf)
  -l <filename> -- log file name with path (default is /var/log/collectd.log)
  -v -- switch on some verbose output
  -d -- run in daemon mode (detached from terminal)

Example:

  ./collectord.py -c collectord.conf -v -l youlogfile.log


Config file consists of sections, that specify collector ID. You need to fill
bind address and port and specify collector type (netflow5, netflow9, ipfix,
syslog). Note, that ipfix type is not supported yet.

Right now it just saves captured messages and flows to netflow.log and 
syslog.log files
