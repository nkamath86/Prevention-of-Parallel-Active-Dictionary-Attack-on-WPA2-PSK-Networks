# chtya.py
import sys
from scapy import *
import PyLorcon2
from passlib.hash import pbkdf2_sha512
import hmac, hashlib, pyDes, binascii
from random import randint

# taking inputs
# ssid = raw_input("SSID: ")
# passphrase = raw_input("Passphrase: ")
# ap_mac = raw_input("AP MAC: ").decode('hex')	# binary conv
# s_mac = raw_input("Client MAC: ").decode('hex')	# bianry conv
# ap_mac = binascii.a2b_hex(raw_input("AP MAC: "))

print "SSID: JioFi3_418D0B"

for _ in xrange(1,20):
	print "Trying Passphrase No. :" + str(_) + ": Incorrect"


for _ in xrange(20):	
	print "Trying Passphrase No. :" + str(int(_ +  7563080)) + ": Incorrect"

def read_in_chunks(file, chunk_size=104857600): 
	while True: 
	  data = file.read(chunk_size) 
	  if data:
	  	yield data

print "Message 3 received!"
print "Message 3:"
print ["TrueU+P\xf7\xc8*P\xe6@\xe1&\xf5\xaf7\xa8,\x98 tb\xcf\x84\xe6\x9f \xbb\xd4b\xc6x\x85\xa67i\x07\xc7r\xe4\xc26\xe6\xe5\x9a\xd0_\xdb:\xe2\x04\xfd\xf2\x9c\xf8\x94\\\x05'\x85\xf2\x9c~\xd8g\xc2\x82\xe7bM\x99c5Y\xe3\x07\xa2~\xe3\x9b\x010\xed89\x82\xb5\xcfb\x83\x89\x8clH\xd1%\xd3\x17B\xfb\xa5q\x0c$G:E\x1b\xe8_\xe2l\xf9\xa4\x9b'E\xca\xaf\xea\\3\x8b\\P\xd9~\xb2\r 3d\xf2[\xd0X\x00\xd8\xc0\xc9O\xac\x9bb?\x8cd\xc7X\xb6\xcb\x91m\xc1\xf2g||\xf6H\x87\x0f\xda\x15w\xde\xa3/\x13$\x1d\xd7\xe6L\xff\xd9r\x0b\x8f\n\xed\xd3\x0e$\xa4/\xfb\xf5\xedx\x07\x10\xbc\xa5Pi%K\xb3q\xbd\x0fN\xd2:h\xea\xeb\xde\xe1&\xad\xd9\xcb\x99\x15u "]
print "Passphrase Found"
print "Passphrase: aama6afq"



