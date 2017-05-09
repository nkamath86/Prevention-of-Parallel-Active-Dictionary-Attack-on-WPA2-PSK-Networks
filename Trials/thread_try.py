import threading
import time
import socket
import sys
from random import randint
from passlib.hash import pbkdf2_sha512
import hmac, hashlib, pyDes

ssid='WIFINAME'

def read_in_chunks(file): 
	# , chunk_size=104857600
	while True: 
	  data = file.readline() 
	  if data:
	  	yield data


def OverallCode(passphrase):
	# things just got serious
	ssid='WIFINAME'
	# passphrase='Password'
	#gc=[bin(randint(0,65535)),bin(0)

	destination_addr = '\x70\x1a\x04\xe8\xe1\x7c'
	source_addr = '\x50\xb7\xc3\xe5\x7d\x09'
	# Create a TCP/IP socket
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


	# function to decrypt gc
	def dec(PMK, gc):   
		key =  bin(int(PMK[:4],16))[2:] # first 24 Bytes of PMK
		cipher = pyDes.triple_des(key).decrypt('' + gc, padmode = 2)
		return cipher

	def inc(gc):    # func to increment gc
		gc[1] = bin(int(gc[1],2)+1) 
		temp = gc[0]
		if len(gc[1]) == 19:	# reset after filling 16 bits
		    gc[1] = bin(0)
		    gc[0] = bin(randint(0,65535)) 
		    while temp == gc[0]:
		        gc[0] = bin(randint(0,65535))
		return gc

	def enc(PMK, gc):   
		 key =  bin(int(PMK[:4],16))[2:] # first 24 Bytes of PMK
		 cipher = pyDes.triple_des(key).encrypt('' + gc[0] + gc[1], padmode = 2)
		 return cipher
	# Connect the socket to the port where the server is listening
	server_address = ('192.168.43.40', 6677)
	#print >>sys.stderr, 'connecting to %s port %s' % server_address
	sock.connect(server_address)




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


	#message 1
	#data1=sock.recv(16).encode('hex')
	#data2=sock.recv(16).encode('hex')

	gc=sock.recv(22).split('/')
	#gc=[]
	#gc.append(dec(PMK,data1).split('/'))
	#gc.append( dec(PMK,data2).split('/'))

	#print 'message1 ='+ data.encode('hex') 

	# PTK
	key_data = min(destination_addr,source_addr) + max(destination_addr,source_addr) + str(gc[0]) + str(gc[1])

	#gc[1]=bin(int(gc[1],2)+1)
	key_data += str(gc[0]) + str(gc[1])
	print key_data.encode('hex')
	print gc[0]
	print gc[1]
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

	#PTK1 = PRF383(PMK, pke, key_data).encode('hex')	# hex string of 96 
	PTK=sock.recv(1024)


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



	#message 2 send to AP
	#GC = dec(PMK, GC)

	#gc[0] = GC[:18]
	#gc[1] = GC[18:]	
	EAPoL_header=''
	# Calculation of MIC
	MIC = hmac.new(KCK, EAPoL_header, hashlib.sha512).digest()
	print MIC.encode('hex')

	packet = enc(PMK,gc)+'\x00\x00\x00'+MIC
	print packet.encode('hex')	
	#send message 2
	sock.sendall(packet)

	#get meassage 3 or message 4
	data = sock.recv(156)
	print data.split('/')[0]





class myThread (threading.Thread):
	def __init__(self, threadID, name, counter, file):
		threading.Thread.__init__(self)
		self.threadID = threadID
		self.name = name
		self.counter = counter
		self.file = file

	def run(self):
		print "Starting " + self.name
		# print_time(self.name, self.counter, 5)
		for j in read_in_chunks(self.file):
			# print j, self.name
			OverallCode(j)
		print "Exiting " + self.name

# Create new threads
# f = open("/home/nagendra/Desktop/2.txt",'r')
thread1 = myThread(1, "Thread-1", 1, open("/home/nagendra/Desktop/0.txt",'r'))
thread2 = myThread(2, "Thread-2", 2, open("/home/nagendra/Desktop/1.txt",'r'))

# Start new Threads
thread1.start()
thread2.start()
thread1.join()
thread2.join()
print "Exiting Main Thread"
f.close()