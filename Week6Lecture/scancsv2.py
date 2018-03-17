from CSVPacket import Packet, CSVPackets
import sys
import argparse

def print_sort_dict(dict):
    for key, value in sorted(dict.iteritems(), key=lambda (k,v): (v,k)):
        print "%s\t:\t%s" % (key, value)

def countip(pkt, dic):
	if not dic.has_key(pkt.ipdst):
		dic[pkt.ipdst] = 0
	if not dic.has_key(pkt.ipsrc):
		dic[pkt.ipsrc] = 0
	dic[pkt.ipdst] += 1
	dic[pkt.ipsrc] += 1

def countip_set(pkt, dic):
	if not dic.has_key(pkt.ipdst):
		dic[pkt.ipdst] = set()
	if not dic.has_key(pkt.ipsrc):
		dic[pkt.ipsrc] = 0
	dic[pkt.ipdst] += 1
	dic[pkt.ipsrc] += 1

parser = argparse.ArgumentParser()
parser.add_argument("csvfile")
parser.add_argument("-stats", action="store_true")
parser.add_argument("-countip", action="store_true")
parser.add_argument("-filtered", action="store_true")
parser.add_argument("-connto", action="store_true")
args = parser.parse_args()

IPProtos = [0 for x in range(256)]
Ports_tcp = [0 for x in range(1024)]
Ports_udp = [0 for x in range(1024)]
IP = {}
IPSRC = {}
IPPORT = {}
GRE = {}
IPSEC = {}
OSPF = {}
numBytes = 0
numPackets = 0

csvfile = open(args.csvfile,'r')

for pkt in CSVPackets(csvfile):
    # pkt.__str__ is defined...
    #print pkt.tcpport
    countip(pkt, IP)
    if args.filtered:
        if pkt.proto == 47:
            countip(pkt, GRE)
        elif pkt.proto == 50:
            countip(pkt, IPSEC)
        elif pkt.proto == 89:
            countip(pkt, OSPF)
    if pkt.ipsrc and pkt.ipdst:
        if not IPSRC.has_key(pkt.ipdst):
            IPSRC[pkt.ipdst] = set()
        IPSRC[pkt.ipdst].add(pkt.ipsrc)
        if not IPPORT.has_key(pkt.ipdst):
            IPPORT[pkt.ipdst] = set()
        if pkt.tcpdport and pkt.tcpdport < 1024:
            Ports_tcp[pkt.tcpdport] += 1
            IPPORT[pkt.ipdst].add(("tcp", pkt.tcpdport))
        if pkt.udpdport and pkt.udpdport < 1024:
            Ports_udp[pkt.udpdport] += 1
            IPPORT[pkt.ipdst].add(("udp", pkt.udpdport))
    numBytes += pkt.length
    numPackets += 1
    proto = pkt.proto & 0xff
    IPProtos[proto] += 1

if args.stats:
    print "TCP"
    for i in range(1024):
        if Ports_tcp[i] != 0:
            print "%3u: %9u" % (i, Ports_tcp[i])
    print "UDP"
    for i in range(1024):
        if Ports_udp[i] != 0:
            print "%3u: %9u" % (i, Ports_udp[i])

if args.countip:
    print_sort_dict(IP)

if args.filtered:
    print "GRE Addresses:" 
    print_sort_dict(GRE)
    print "IPSEC Addresses:"
    print_sort_dict(IPSEC)
    print "OSPF Addresses:"
    print_sort_dict(OSPF)
if args.connto:
    for ipdst in sorted(IPSRC.keys(), key=lambda key: len(IPSRC[key])):
        port_str = ""
        for port in IPPORT[ipdst]:
            port_str += "%s/%s, " % (port[0], port[1])
        print "ipdst %s has %s distinct ipsrc on ports: %s" % (ipdst, len(IPSRC[ipdst]), port_str)
        
#print "numPackets:%u numBytes:%u" % (numPackets,numBytes)
#for i in range(256):
#    if IPProtos[i] != 0:
#        print "%3u: %9u" % (i, IPProtos[i])