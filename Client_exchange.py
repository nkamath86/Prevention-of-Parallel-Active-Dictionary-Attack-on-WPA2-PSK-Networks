# version 2.0
# client side 
# version 1.0
# Client Side - Existing and Proposed 
import sys
import PyLorcon2
from scapy.all import *
from passlib.hash import pbkdf2_sha256
import hmac, hashlib, pyDes
from random import randint

# interface = "wlan0mon"

# taking inputs
# ssid = raw_input("SSID: ")
# passphrase = raw_input("Passphrase: ")
# ap_mac = raw_input("AP MAC: ").decode('hex')	# binary conv
# s_mac = raw_input("Client MAC: ").decode('hex')	# bianry conv

print ''

# sample inputs for testing purposes only
ssid = 'WIFINAME'
passphrase = 'Password'
ap_mac = 'fafafafa'.decode('hex')
s_mac = 'fafafafa'.decode('hex')


# SNonce - Client Side nonce - 32bit random number
SNonce = bin(randint(0,2**32))
print "SNonce : " + str(SNonce)

# ANonce - Access Point nonce - 32bit random number
# To be extracted from Message 1 but generated here for now
ANonce = bin(randint(0,2**32))
print "ANonce : " + str(ANonce)

print ''

# Key Generation
# PSK  
print 'PSK: ' 
PSK = pbkdf2_sha256.using(salt = ssid, salt_size = len(ssid), rounds = 4096).hash(passphrase)
PSK = str(PSK.split('$')[4]).replace('.','+')+'=='
PSK = PSK.decode('base64').encode('hex')
# print PSK, len(PSK)
print PSK
print 'Length of PSK (bits): ' + str(int(len(PSK))*4) + '\n'

# PMK 
print 'PMK: '
PMK = pbkdf2_sha256.using(salt = ssid, salt_size = len(ssid), rounds = 4096).hash(PSK)
PMK = str(PMK.split('$')[4]).replace('.','+')+'=='
PMK = PMK.decode('base64').encode('hex')
# print PMK, len(PMK)
print PMK
print 'Length of PMK (bits): ' + str(int(len(PMK))*4) + '\n'

# PTK
key_data = min(ap_mac,s_mac) + max(ap_mac,s_mac) + min(ANonce, SNonce) + max(ANonce, SNonce)
pke = "Pairwise key expansion"  

# Install PTK to be received from the access point 
# But for convenience, we use Install_PTK = True
Install_PTK = True

def PRF383(key,A,B):  # function for PRF383
    blen = 48	# 384 bits # number of bytes = 48
    i    = 0
    R    = ''
    while i <= ((blen*8+159)/160):
        hmacsha256 = hmac.new(key, A+chr(0x00)+B+chr(i), hashlib.sha256)
        i += 1
        R += hmacsha256.digest()
    return R[:blen]

if Install_PTK:
	PTK = PRF383(PMK, pke, key_data).encode('hex')	# hex string of 96 
	# Other Keys
	KCK = PTK[:32]
	KEK = PTK[32:64]
	TK = PTK[64:]
	print 'PTK: ' + '\n' + PTK

print 'Length of PTK (bits): ' + str(len(PTK)*4) + '\n'
print 'KCK: ' + '\n' + KCK
print 'Length of KCK (bits): ' + str(len(KCK)*4) + '\n'
print 'KEK: ' + '\n' + KEK
print 'Length of KEK (bits): ' + str(len(KEK)*4) + '\n'
print 'TK: ' + '\n' + TK
print 'Length of TK (bits): ' + str(len(TK)*4) + '\n'

# Calculating MIC# Calculating MIC

def packet_print(packet):
	return "Message: %s" % (packet.load)

# EAPoL_header = "Insert Valid EAPoL header data here".encode('hex')
EAPoL_header = str(sniff(filter = "ip and host 192.168.43.40", prn = packet_print)).encode('hex')
MIC = hmac.new(KCK, EAPoL_header, hashlib.sha256).digest()

# Message Generation
# sniff(filter = "ip and host 192.168.43.40", prn = packet_print)

# Message 2
message2 = MIC + SNonce  # MIC & unencrypted SNonce in message2 by client
a = IP(src = "192.168.43.49", dst = "192.168.43.40") /Ether(dst = "70:1a:04:e8:e1:7c")/ Raw(load = message2)
send(a)

# Message 3
EAPoL_header = str(sniff(filter = "ip and host 192.168.43.40", prn = packet_print)).encode('hex')
MIC = hmac.new(KCK, EAPoL_header, hashlib.sha256).digest()

# Message 4
message4 = MIC    # message4 sent by client 
a = IP(src = "192.168.43.49", dst = "192.168.43.40") /Ether(dst = "70:1a:04:e8:e1:7c")/ Raw(load = message4)
send(a)

# End of handshake
# Output messages

# print 'message1: '
# print [message1]
# print ''

# print 'message2: '
# print [message2]
# print ''

# # print 'message3: '
# # print [message3]
# # print ''

# print 'message4: '
# print [message4]
# print ''

