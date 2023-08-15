.PHONY: nslookup dig

nslookup:
	nslookup example.com 127.0.0.1

dig:
	dig @127.0.0.1 example.com

scapy:
	python3 -c 'from scapy.all import *; print(sr(IP(src="127.0.0.1", dst="127.0.0.1")/UDP(sport=61234, dport=53)/DNS(rd=1,qd=DNSQR(qname="example.com")), timeout=3, retry=0)[0][0].answer[2].show())'