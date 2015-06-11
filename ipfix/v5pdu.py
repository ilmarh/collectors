#
# python-ipfix (c) 2013 Brian Trammell.
#
# Many thanks to the mPlane consortium (http://www.ict-mplane.eu) for
# its material support of this effort.
# 
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""
Provides the PduBuffer class for decoding NetFlow V5 Protocol Data 
Units (PDUs) from a stream.

"""

from . import template, types, ie
from .template import IpfixEncodeError, IpfixDecodeError
from .message import accept_all_templates

import operator
import functools
import struct
from datetime import datetime
from warnings import warn

NETFLOW5_VERSION = 5
NETFLOW5_RECLEN = 48
"""
Bytes	Contents	     Description
0-1	version	             NetFlow export format version number
2-3	count	             Number of flows exported in this packet (1-30)
4-7	sys_uptime	     Current time in milliseconds since the export device booted
8-11	unix_secs	     Current count of seconds since 0000 UTC 1970
12-15	unix_nsecs	     Residual nanoseconds since 0000 UTC 1970
16-19	flow_sequence	     Sequence counter of total flows seen
20	engine_type	     Type of flow-switching engine
21	engine_id	     Slot number of the flow-switching engine
22-23	sampling_interval    First two bits hold the sampling mode; remaining 14 bits hold value of sampling interval
"""

_sethdr_st = struct.Struct("!HH")
_pduhdr_st = struct.Struct("!HHLLLLBBH")
_pdudata_st = struct.Struct("!LLLHHLLLLHHBBBBHHBBH")
"""
Bytes	Contents     Description
0-3	srcaddr	     Source IP address | sourceIPv4Address(8)<ipv4Address>[4]
4-7	dstaddr	     Destination IP address | destinationIPv4Address(12)<ipv4Address>[4]
8-11	nexthop	     IP address of next hop router | ipNextHopIPv4Address(15)<ipv4Address>[4]
12-13	input	     SNMP index of input interface | ingressInterfaceType(368)<unsigned32>[4] !!!
14-15	output	     SNMP index of output interface | egressInterfaceType(369)<unsigned32>[4] !!!
16-19	dPkts	     Packets in the flow | packetDeltaCount(2)<unsigned64>[8] !!!
20-23	dOctets	     Total number of Layer 3 bytes in the packets of the flow | octetDeltaCount(1)<unsigned64>[8] !!!
24-27	first	     SysUptime at start of flow | flowStartSysUpTime(22)<unsigned32>[4]
28-31	last	     SysUptime at the time the last packet of the flow was received | flowEndSysUpTime(21)<unsigned32>[4]
32-33	srcport	     TCP/UDP source port number or equivalent | sourceTransportPort(7)<unsigned16>[2]
34-35	dstport	     TCP/UDP destination port number or equivalent | destinationTransportPort(11)<unsigned16>[2]
36	pad1	     Unused (zero) bytes | samplerMode(49)<unsigned8>[1]
37	tcp_flags    Cumulative OR of TCP flags | tcpControlBits(6)<unsigned16>[2] !!!
38	prot	     IP protocol type (for example, TCP = 6; UDP = 17) | protocolIdentifier(4)<unsigned8>[1]
39	tos	     IP type of service (ToS) | ipClassOfService(5)<unsigned8>[1]
40-41	src_as	     Autonomous system number of the source, either origin or peer | bgpSourceAsNumber(16)<unsigned32>[4] !!!
42-43	dst_as	     Autonomous system number of the destination, either origin or peer | bgpDestinationAsNumber(17)<unsigned32>[4] !!!
44	src_mask     Source address prefix mask bits | sourceIPv4PrefixLength(9)<unsigned8>[1] 
45	dst_mask     Destination address prefix mask bits | destinationIPv4PrefixLength(13)<unsigned8>[1]
46-47	pad2	     Unused (zero) bytes | 
"""
ie.use_iana_default()
ie.for_spec("oldIngressInterfaceType(33333/11368)<unsigned16>[2]")
ie.for_spec("oldEgressInterfaceType(33333/11369)<unsigned16>[2]")
ie.for_spec("oldPacketDeltaCount(33333/11002)<unsigned32>[4]")
ie.for_spec("oldOctetDeltaCount(33333/11001)<unsigned32>[4]")
ie.for_spec("oldTcpControlBits(33333/11006)<unsigned8>[1]")
ie.for_spec("oldBgpSourceAsNumber(33333/11016)<unsigned16>[2]")
ie.for_spec("oldBgpDestinationAsNumber(33333/11017)<unsigned16>[2]")
ie.for_spec("oldPad1(33333/11111)<unsigned8>[1]")
ie.for_spec("oldPad2(33333/11112)<unsigned16>[2]")
tmpl_v5 = template.from_ielist(257,
     ie.spec_list([ "sourceIPv4Address",
                    "destinationIPv4Address",
                    "ipNextHopIPv4Address",
                    "oldIngressInterfaceType",
                    "oldEgressInterfaceType",
                    "oldPacketDeltaCount",
                    "oldOctetDeltaCount",
                    "flowStartSysUpTime",
                    "flowEndSysUpTime",
                    "sourceTransportPort",
                    "destinationTransportPort",
                    "oldPad1",
                    "oldTcpControlBits",
                    "protocolIdentifier",
                    "ipClassOfService",
                    "oldBgpSourceAsNumber",
                    "oldBgpDestinationAsNumber",
                    "sourceIPv4PrefixLength",
                    "destinationIPv4PrefixLength",
                    "oldPad2" ]))


class PduBuffer(object):
    """
    Implements a buffer for reading NetFlow V5 PDUs from a stream or packet.
    
    Abstract class; use the :meth:`from_stream` to get an instance for
    reading from a stream instead.
    """
    def __init__(self):
        """Create a new PduBuffer instance."""
        self.mbuf = memoryview(bytearray(65536))

        self.length = 0
        self.cur = 0
        
        self.reccount = None
        self.sequence = None
        self.export_epoch = None
        self.sysuptime_ms = None
        self.basetime_epoch = None
        self.odid = 0
        self.nanosecs = 0
        self.engine_type = None
        self.engine_id = None
        self.samp_int = 0

        self.sequences = {}
        tmpl_v5 = None
        

    def __repr__(self):
        return "<PDUBuffer domain "+str(self.odid)+\
               " length "+str(self.length)+addinf+">"

    def _increment_sequence(self, inc = 1):
        self.sequences.setdefault(self.odid, 0)
        self.sequences[self.odid] += inc

    def _parse_pdu_header(self):
        (version, self.reccount, self.sysuptime_ms, self.export_epoch, self.nanosecs, self.sequence, self.engine_type, self.engine_id, self.samp_int) = \
             _pduhdr_st.unpack_from(self.mbuf, 0)
        
        if version != NETFLOW5_VERSION:
            raise IpfixDecodeError("Illegal or unsupported version " + 
                                   str(version))
        
        self._increment_sequence(self.reccount)
        self.basetime_epoch = self.export_epoch - (self.sysuptime_ms / 1000)

    def set_iterator(self):
        """
        Low-level interface to set iteration.

        """
        while True:
            try:
                yield self.next_set()
            except EOFError:
                break

    def record_iterator(self, ielist=None) : #, decode_fn=template.Template.decode_namedict_from, tmplaccept_fn=accept_all_templates, recinf=None):
        """
        Low-level interface to record iteration.
        
        Iterate over records in a PDU; the buffer must either be attached to 
        a stream via :meth:`attach_stream` or have been preloaded with 
        :meth:`from_bytes`. Automatically handles 
        templates in set order. By default, iterates over each record in the 
        stream as a dictionary mapping IE name to value 
        (i.e., the same as :meth:`namedict_iterator`)
        For V5 Netflow record template is fixed in RFC, so just fill in data
        from PDU in IPFIX format
        
        :param ielist: if None - decode as dict, else - decode as tuples according to ielist
        
        """
        for (mbuf, offset, setlen) in self.set_iterator():
                
            setend = offset + setlen
            offset += _pduhdr_st.size # skip set header in decode
	    #for i in range(0, self.reccount):
            while offset + tmpl_v5.minlength <= setend:
                (rec, offset) = tmpl_v5.decode_namedict_from(mbuf, offset)
                yield rec
                self._increment_sequence()


    def namedict_iterator(self):
        """
        Iterate over all records in the Message, as dicts mapping IE names
        to values.
        
        :returns: a name dictionary iterator
        
        """
        
        return self.record_iterator() #  decode_fn = template.Template.decode_namedict_from)


    def tuple_iterator(self, ielist):
        """
        Iterate over all records in the PDU containing all the IEs in 
        the given ielist. Records are returned as tuples in ielist order.
        
        :param ielist: an instance of :class:`ipfix.ie.InformationElementList`
                       listing IEs to return as a tuple
        :returns: a tuple iterator for tuples as in ielist order
        
        """
        
        return self.record_iterator(ielist)

class StreamPduBuffer(PduBuffer):
    """Create a new StreamPduBuffer instance."""
    def __init__(self, stream):
        super(StreamPduBuffer, self).__init__()
        
        self.stream = stream
    
    def next_set(self):
        """
        Reads the next set from the stream. Automatically reads PDU headers, as
        well, since PDU headers are treated as a special case of set header in
        streamed PDU reading.
    
        Raises EOF to signal end of stream.
    
        Yes, NetFlow V5 really is that broken as a storage format,
        and this is the only way to stream it without counting records 
        (which we can't do in the tuple-reading case).
    
        """
        sethdr = self.stream.read(_pduhdr_st.size)
        if (len(sethdr) == 0):
            raise EOFError()
        elif (len(sethdr) < _pduhdr_st.size):
            raise IpfixDecodeError("Short read in V5 set header ("+ 
                                       str(len(sethdr)) +")")
        
        self.mbuf[0:_pduhdr_st.size] = sethdr
        self._parse_pdu_header()

        # read the set body into the buffer
        setlen = self.reccount*NETFLOW5_RECLEN
        setbody = self.stream.read(setlen)
        if (len(setbody) < setlen):
            raise IpfixDecodeError("Short read in V5 set body ("+ 
                                    str(len(setbody)) +")")

        self.mbuf[_pduhdr_st.size:_pduhdr_st.size+setlen] = setbody
    
        # return pointers for set_iterator
        return (self.mbuf, 0, setlen)

def from_stream(stream):
    """
    Get a StreamPduBuffer for a given stream
    
    :param stream: stream to read
    :return: a :class:`PduBuffer` wrapped around the stream.

    """
    return StreamPduBuffer(stream)

class TimeAdapter:
    """
    Wraps around a PduBuffer and adds flowStartMilliseconds and 
    flowEndMilliseconds Information Elements to each record, turning
    the basetime-dependent timestamps common in V9 export into
    absolute timestamps.

    To use, create a PduBuffer, create a TimeAdapter with the PduBuffer
    as the constructor argument, then iterate tuples or namedicts from
    the TimeAdapter.

    """
    
    def __init__(self, pdubuf):
        self.pdubuf = pdubuf
        
    def namedict_iterator(self):
        for rec in self.pdubuf.namedict_iterator(ienames):
            try: 
                rec["flowStartMilliseconds"] = \
                    types._decode_msec(rec["flowStartSysUpTime"] / 1000 +
                                       self.pdubuf.basetime_epoch)
            except KeyError:
                pass
        
            try: 
                rec["flowEndMilliseconds"] = \
                    types._decode_msec(rec["flowEndSysUpTime"] / 1000 +
                                       self.pdubuf.basetime_epoch)
            except KeyError:
                pass
        
            yield rec
        
    def tuple_iterator(self, ielist):
        flowStartSysUpTime = ie.for_spec("flowStartSysUpTime")
        flowEndSysUpTime = ie.for_spec("flowEndSysUpTime")
        
        if (flowStartSysUpTime in ielist) and \
           (flowEndSysUpTime in ielist):
            start_index = ielist.index(flowStartSysUpTime)
            end_index = ielist.index(flowEndSysUpTime)

            for rec in self.pdubuf.tuple_iterator(ielist):                
                start_ms = types._decode_msec(rec[start_index] / 1000 + 
                                 self.pdubuf.basetime_epoch)
                end_ms = types._decode_msec(rec[end_index] / 1000 + 
                                  self.pdubuf.basetime_epoch)
                yield rec + (start_ms, end_ms)
        else:
            for rec in self.pdubuf.tuple_iterator(ielist):
                yield rec
    
