from scapy.all import *
def packet_print(packet):
	return "%s, %s, %s" % (packet.src, packet.dst, packet.load)

sniff(filter = "ip and host 192.168.43.40", prn = packet_print)