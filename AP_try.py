from scapy.all import *
src_ip = "192.168.43.40"
dst_ip = "192.168.43.49"
data = "Hello"
a = IP(src = src_ip, dst = dst_ip) /Ether(dst = "50:b7:c3:e5:7d:09")/ Raw(load = data)
send(a)