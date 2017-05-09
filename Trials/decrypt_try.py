import pyDes

PMK = 'd7b232f35ee611883b2f9ea4d718e6b13c1985926d0c5970ec1a2fc589ac632e8f535bd4ddc3fefbd1934fafd49f6e3c04fc3e28216bf3adc7fd7e47aeae3a7e'
PMK1 = 'adb3369937ec9723daf3af62cc22e1970581282ef22c7e32ef61a4e9e2b621f0152efe15dae5996a9a86d85165099afba799970a8f7585172666df9175e683e9'
data = "hello world"

def enc(PMK, gc):   
    key = bin(int(PMK[:4],16))[2:] # first 24 Bytes of PMK
    cipher = pyDes.triple_des(key).encrypt(gc, padmode = 2)
    return cipher

def dec(PMK, gc):   
    key = bin(int(PMK[:4],16))[2:] # first 24 Bytes of PMK
    cipher = pyDes.triple_des(key).decrypt(gc, padmode = 2)
    return cipher

# msg1 = enc(PMK1, data)
# print 'msg1 = ' + msg1

# msg2 = dec(PMK1, enc(PMK,data))
# print 'msg2 = ' + msg2

print enc(PMK, data)
print enc(PMK1, data)
print pyDes.triple_des(bin(int(PMK[:4],16))[2:]).encrypt(data, padmode = 2)
print pyDes.triple_des(bin(int(PMK1[:4],16))[2:]).encrypt(data, padmode = 2)