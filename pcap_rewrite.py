#!/usr/bin/env python

import logging, sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

# Add some colouring for printing packets later
YELLOW = '\033[93m'
GREEN = '\033[92m'
END = '\033[0m'
RED = '\033[91m'

if len(sys.argv) != 7:
	print 'Usage is ./pcap-rewrite.py <input pcap file> <source ip> <destination ip> <source port> <dest port> <output pcap file>'
	print 'Example - ./pcap-rewrite.py sample.pcap 192.168.1.1 192.168.1.254 1234 80 /tmp/out.pcap'
	sys.exit(1)

pcap = sys.argv[1]

s_ip = sys.argv[2]
d_ip = sys.argv[3]
s_port = sys.argv[4]
d_port= sys.argv[5]
outfile = sys.argv[6]

pkts = rdpcap(pcap)

# Find the first packet and use that as the reference for source and destination IP address
sip = pkts[0][IP].src
dip = pkts[0][IP].dst
sport = pkts[0][TCP].sport
dport = pkts[0][TCP].dport

print GREEN + '[+] Welcome to my scapy pcap rewriter...Enjoy!! @catalyst256' + END
print GREEN + '[+] added option to change ports @hardik05' + END
print YELLOW + '[!] The address of ' + sip + ' will be overwritten with ' + s_ip + END
print YELLOW + '[!] The address of ' + dip + ' will be overwritten with ' + d_ip + END
print YELLOW + '[!] The source port ' + str(sport) + ' will be overwritten with ' + s_port + END
print YELLOW + '[!] The destination port ' + str(dport) + ' will be overwritten with ' + d_port + END
# Delete the IP and TCP checksums so that they are recreated when we change the IP addresses
print YELLOW + '[-] Deleting old checksums so that scapy will regenerate them correctly' + END
for p in pkts:
	del p[IP].chksum
	del p[TCP].chksum

# Rewrite the packets with the new addresses
print YELLOW + '[-] Rewriting source and destination IP addresses' + END
for p in pkts:
	if p.haslayer(IP):
		if ((p[IP].src == sip) and (p[TCP].sport == sport)):
			p[IP].src = s_ip
			p[IP].dst = d_ip
                        p[TCP].sport=int(s_port)
                        p[TCP].dport=int(d_port)
                        # print p[IP].dst
		if ((p[IP].dst == sip) and (p[TCP].sport == dport)):
			p[IP].src = d_ip
			p[IP].dst = s_ip
                        p[TCP].sport=int(d_port)
                        p[TCP].dport=int(s_port)

# Write the packets out to a new file
print GREEN + '[!] Writing out pkts to new file ' + outfile	+ END
wrpcap(outfile, pkts)

print GREEN + '[!] All done!!!' + END
