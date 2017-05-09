# Ap to client trial for eapol
from scapy.all import *
import PyLorcon2
from random import randint
from passlib.hash import pbkdf2_sha512
import hmac, hashlib, pyDes

interface = "wlan0"
ssid = 'WIFINAME'
passphrase = 'Password'

gc = [bin(randint(0,65535)),bin(0)]   # randomly generated value for first 16 bits 
def inc(gc):    # func to increment gc
    gc[1] = bin(int(gc[1],2)+1) 
    temp = gc[0]
    if len(gc[1]) == 19:	# reset after filling 16 bits
        gc[1] = bin(0)
        gc[0] = bin(randint(0,65535)) 
        while temp == gc[0]:
            gc[0] = bin(randint(0,65535))
    return gc

# function to encrypt gc
def enc(PMK, gc):   
    key =  bin(int(PMK[:4],16))[2:] # first 24 Bytes of PMK
    cipher = pyDes.triple_des(key).encrypt('' + gc[0] + gc[1], padmode = 2)
    return cipher


interface = "wlan0mon"

injector = PyLorcon2.Context(iface = interface)	# creating PyLorcon Object
injector.open_injmon()	# open context in inject and monitor mode
# injector.get_channel()	# returns 3
# print ':'.join(str(i) for i in injector.get_hwmac())
# injector.set_channel(21) # channel set to 11 # ?
# injector.send_bytes(packet)	ost probable way to send

# defining addresses
destination_addr = '\x50\xb7\xc3\xe5\x7d\x09'
source_addr = '\x70\x1a\x04\xe8\xe1\x7c'
bss_id_addr = source_addr	# AP to Client

# message 1
packet = '\xb0\x00'	# mgmt/auth frame 
packet += '\x00\x00'
packet += destination_addr
packet += source_addr
packet += bss_id_addr

# sequence number
packet += '\x90\x70'
packet += 'Message 1 = '
packet += str(gc[0]) + str(gc[1])

# send packet
for _ in xrange(15):
	injector.send_bytes(packet)

# gc just got incremented 
gc = inc(gc)

# ------------------------------------------------------------- #
# message 2 
# sniffing MIC and GC+1
S_MIC = ''
EAPoL_header = '' 

def sniffEAPoL(p):
	# if p.haslayer(WPA_key):
	# 	layer = p.getlayer(WPA_key)

	# key_info = layer.key_info
	# wpa_key_length = layer.wpa_key_length
	# replay_counter = layer.replay_counter
	# WPA_KEY_INFO_INSTALL = 64
	# WPA_KEY_INFO_ACK = 128
	# WPA_KEY_INFO_MIC = 256

	# if ((key_info & WPA_KEY_INFO_MIC) and 
	# 		(key_info & WPA_KEY_INFO_ACK == 0) and 
	# 		(key_info & WPA_KEY_INFO_INSTALL == 0) and 
	# 		(wpa_key_length > 0)) :
	# 		print str(p)
	if p[0].haslayer(EAPOL):
		print p[0]
		print p[EAPOL].data
		print 'Message 2 = '
		global S_MIC
		global EAPoL_header 
		EAPoL_header = p[EAPOL]
		S_MIC = p[EAPOL].data.split('Message 2 = ')[1].split('/')[1]
		

sniff(iface = interface, prn = sniffEAPoL, filter = 'ether dst 70:1a:04:e8:e1:7c')
gc = inc(gc)

# -------------------------------------------------------------- #
# Procedure after Message 1 and 2
# Key Generation
# PSK - 512 bits 
print 'PSK: ' 
PSK = pbkdf2_sha512.using(salt = ssid, salt_size = len(ssid), rounds = 4096).hash(passphrase)
PSK = str(PSK.split('$')[4]).replace('.','+')+'=='
PSK = PSK.decode('base64').encode('hex')
# print PSK, len(PSK)
print PSK
print 'Length of PSK (bits): ' + str(int(len(PSK))*4) + '\n'


# PMK 
print 'PMK: '
PMK = pbkdf2_sha512.using(salt = ssid, salt_size = len(ssid), rounds = 4096).hash(PSK)
PMK = str(PMK.split('$')[4]).replace('.','+')+'=='
PMK = PMK.decode('base64').encode('hex')
# print PMK, len(PMK)
print PMK
print 'Length of PMK (bits): ' + str(int(len(PMK))*4) + '\n'

# PTK
key_data = min(source_addr,destination_addr) + max(source_addr,destination_addr) + gc[0] + gc[1]
gc = inc(gc)
key_data += gc[0] + gc[1]
pke = "Pairwise key expansion"  

def PRF383(key,A,B):  # function for PRF383
    blen = 48	# 384 bits # number of bytes = 48
    i    = 0
    R    = ''
    while i <= ((blen*8+159)/160):
        hmacsha512 = hmac.new(key, A+chr(0x00)+B+chr(i), hashlib.sha512)
        i += 1
        R += hmacsha512.digest()
    return R[:blen]

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

# Calculation of MIC
MIC = hmac.new(KCK, EAPoL_header, hashlib.sha512).digest()
# now to compare the S_MIC and the MIC generated above

if S_MIC == MIC:
	# will send Message 3 cause the client is legitimate
	key1 = bin(int(KEK[:6],16))[2:]  # KEK used to encrypt GTK
	eGTK = pyDes.triple_des(key1).encrypt(GTK, padmode = 2)  # encrypt GTK with KEK
	gc = inc(gc)
	packet = '\xb0\x00'	# mgmt/auth frame
	packet += '\x00\x00'
	packet += destination_addr
	packet += source_addr
	packet += bss_id_addr

	# sequence number
	packet += '\x90\x70'
	packet += 'Message 3 = '
	packet += enc(PMK,gc) + eGTK + gc

	# send packet
	injector.send_bytes(packet)

else:
	# will send Message 4 i.e. the deauth frame
	gc = inc(gc)
	packet = '\xc0\x00'	# mgmt/deauth frame
	packet += '\x00\x00'
	packet += destination_addr
	packet += source_addr
	packet += bss_id_addr

	# sequence number
	packet += '\x90\x70'
	packet += 'Message 4 = '
	packet += 'Wrong Passphrase'

	# send packet
	injector.send_bytes(packet)

# end of handshake

# ------------------------------------------------------------ #

# binary and hex values - first 16 values
# 0b0 0x0
# 0b1 0x1
# 0b10 0x2
# 0b11 0x3
# 0b100 0x4
# 0b101 0x5
# 0b110 0x6
# 0b111 0x7
# 0b1000 0x8
# 0b1001 0x9
# 0b1010 0xa
# 0b1011 0xb
# 0b1100 0xc
# 0b1101 0xd
# 0b1110 0xe
# 0b1111 0xf
