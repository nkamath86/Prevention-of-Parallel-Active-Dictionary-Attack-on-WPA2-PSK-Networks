# EXISTING SYSTEM
# import sys
# import PyLorcon2
from scapy.all import *
from passlib.hash import pbkdf2_sha256
import hmac, hashlib, pyDes
from random import randint

# taking inputs
# ssid = raw_input("SSID: ")
# passphrase = raw_input("Passphrase: ")
# ap_mac = raw_input("AP MAC: ").decode('hex')  # binary conv
# s_mac = raw_input("Client MAC: ").decode('hex')   # bianry conv

# sample inputs for testing purposes only
ssid = 'WIFINAME'
passphrase = 'Password'
ap_mac = 'fafafafa'.decode('hex')
s_mac = 'fafafafa'.decode('hex')

# SNonce - Client Side nonce - 32bit random number
# SNonce = bin(randint(0,2**32))
# print "SNonce : " + str(SNonce)

# ANonce - Access Point nonce - 32bit random number
# ANonce = bin(randint(0,2**32))
# SNonce = ANonce
# print "ANonce : " + str(ANonce)

print ''

# PSK  
# passphrase = EAPoL_header
# print 'PSK: ' 
# PSK = pbkdf2_sha256.using(salt = ssid, salt_size = len(ssid), rounds = 4096).hash(passphrase)
# PSK = str(PSK.split('$')[4]).replace('.','+')+'=='
# PSK = PSK.decode('base64').encode('hex')
# # print PSK, len(PSK)
# print PSK
# print 'Length of PSK (bits): ' + str(int(len(PSK))*4) + '\n'

# # PMK 
# print 'PMK: '
# PMK = pbkdf2_sha256.using(salt = ssid, salt_size = len(ssid), rounds = 4096).hash(PSK)
# PMK = str(PMK.split('$')[4]).replace('.','+')+'=='
# PMK = PMK.decode('base64').encode('hex')
# # print PMK, len(PMK)
# print PMK
# print 'Length of PMK (bits): ' + str(int(len(PMK))*4) + '\n'

# # PTK
# key_data = min(ap_mac,s_mac) + max(ap_mac,s_mac) + min(ANonce, SNonce) + max(ANonce, SNonce)
# pke = "Pairwise key expansion"  

# def PRF383(key,A,B):  # function for PRF383
#     blen = 48   # 384 bits # number of bytes = 48
#     i    = 0
#     R    = ''
#     while i <= ((blen*8+159)/160):
#         hmacsha256 = hmac.new(key, A+chr(0x00)+B+chr(i), hashlib.sha256)
#         i += 1
#         R += hmacsha256.digest()
#     return R[:blen]

# PTK = PRF383(PMK, pke, key_data).encode('hex')  # hex string of 96 

# # Other Keys
# KCK = PTK[:32]
# KEK = PTK[32:64]
# TK = PTK[64:]

# print 'PTK: ' + '\n' + PTK

# print 'Length of PTK (bits): ' + str(len(PTK)*4) + '\n'
# print 'KCK: ' + '\n' + KCK
# print 'Length of KCK (bits): ' + str(len(KCK)*4) + '\n'
# print 'KEK: ' + '\n' + KEK
# print 'Length of KEK (bits): ' + str(len(KEK)*4) + '\n'
# print 'TK: ' + '\n' + TK
# print 'Length of TK (bits): ' + str(len(TK)*4) + '\n'


# def read_in_chunks(file, chunk_size=104857600): 
#     while True: 
#       data = file.read(chunk_size) 
#       if data:
#         yield data

flag = 0    
# EAPoL_header = ''

def cont():
    flag = 1

def parse():
    if passphrase in packet.load:
        cont()
        EAPoL_header = packet.load
        return "Correct Passphrase"
    else: 
        return "Incorrect Passphrase"

# with open("/home/nagendra/Desktop/3.txt", 'r') as f:
#     for i in read_in_chunks() and flag!=1:
#         a = IP(src = "192.168.43.49", dst = "192.168.43.40") /Ether(dst = "70:1a:04:e8:e1:7c")/ Raw(load = str(i))
#         send(a)
#         sniff(filter = "ip and host 192.168.43.40", prn = parse)

while flag !=1:
    sniff(filter = "ip and host 192.168.43.49", prn = parse)


# if flag == 1:
#     # PSK  
#     passphrase = EAPoL_header
#     print 'PSK: ' 
#     PSK = pbkdf2_sha256.using(salt = ssid, salt_size = len(ssid), rounds = 4096).hash(passphrase)
#     PSK = str(PSK.split('$')[4]).replace('.','+')+'=='
#     PSK = PSK.decode('base64').encode('hex')
#     # print PSK, len(PSK)
#     print PSK
#     print 'Length of PSK (bits): ' + str(int(len(PSK))*4) + '\n'

#     # PMK 
#     print 'PMK: '
#     PMK = pbkdf2_sha256.using(salt = ssid, salt_size = len(ssid), rounds = 4096).hash(PSK)
#     PMK = str(PMK.split('$')[4]).replace('.','+')+'=='
#     PMK = PMK.decode('base64').encode('hex')
#     # print PMK, len(PMK)
#     print PMK
#     print 'Length of PMK (bits): ' + str(int(len(PMK))*4) + '\n'

#     # PTK
#     key_data = min(ap_mac,s_mac) + max(ap_mac,s_mac) + min(ANonce, SNonce) + max(ANonce, SNonce)
#     pke = "Pairwise key expansion"  

#     def PRF383(key,A,B):  # function for PRF383
#         blen = 48   # 384 bits # number of bytes = 48
#         i    = 0
#         R    = ''
#         while i <= ((blen*8+159)/160):
#             hmacsha256 = hmac.new(key, A+chr(0x00)+B+chr(i), hashlib.sha256)
#             i += 1
#             R += hmacsha256.digest()
#         return R[:blen]

#     PTK = PRF383(PMK, pke, key_data).encode('hex')  # hex string of 96 

#     # Other Keys
#     KCK = PTK[:32]
#     KEK = PTK[32:64]
#     TK = PTK[64:]

#     print 'PTK: ' + '\n' + PTK

#     print 'Length of PTK (bits): ' + str(len(PTK)*4) + '\n'
#     print 'KCK: ' + '\n' + KCK
#     print 'Length of KCK (bits): ' + str(len(KCK)*4) + '\n'
#     print 'KEK: ' + '\n' + KEK
#     print 'Length of KEK (bits): ' + str(len(KEK)*4) + '\n'
#     print 'TK: ' + '\n' + TK
#     print 'Length of TK (bits): ' + str(len(TK)*4) + '\n'


    


