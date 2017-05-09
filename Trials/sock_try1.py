from socket import socket, AF_PACKET, SOCK_RAW
s = socket(AF_PACKET, SOCK_RAW)
s.bind(("wlan0", 4096))
src_addr = '\x70\x1a\x04\xe8\xe1\x7c'
dst_addr = '\x50\xb7\xc3\xe5\x7d\x09'
payload = 'hello bitch'
# checksum = 
ethertype = '\x08\x01'
s.send(dst_addr+src_addr+ethertype+payload)
message = s.recv(4096)
print s
print s.decode('hex')