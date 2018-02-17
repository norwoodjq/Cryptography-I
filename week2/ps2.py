# -*- coding: utf-8 -*-
"""
Created on Sat Jul 22 17:34:49 2017

@author: John
"""

ctlst = [('140b41b22a29beb4061bda66b6747e14','4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81'),
         ('140b41b22a29beb4061bda66b6747e14','5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253'),
         ('36f18357be4dbd77f050515c73fcf9f2','69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329'),
         ('36f18357be4dbd77f050515c73fcf9f2','770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451')]


from Crypto.Cipher import AES, XOR
from Crypto.Util import Counter
from Crypto import Random
#import Crypto.Util.Padding

NUM_COUNTER_BITS = 128
ctr = Counter.new(NUM_COUNTER_BITS)



def xorb(a,b):
    # xor two unequal hex strings, truncating the longer string
    # i.e. a = '5c5d' b = '5c5d' returns result = '0000'
    #      a = '5c5d' b = '5c' returns result = '00'
    #      a = '5c'   b = '5c5d' returns result = '00'
    rawa = bytes.fromhex(a)
    rawb = bytes.fromhex(b)
    rawresult = bytes(x^y for x,y in zip(rawa,rawb))
    result = rawresult.hex()
    return result

def h(byte_string):
    # convert byte string to hex string
    # i.e., input: b'\x8c\x1b returns: '8c1b'
    return byte_string.hex()

def raw(h):
    # convert hex string to byte string
    # i.e., input: '8c1b'  returns: b'\x8c\x1b
    return bytes.fromhex(h)

def pad(s):
    padnum = AES.block_size - len(s)%AES.block_size
    spad = s + (bytes([padnum])*padnum)
    return spad

def unpad(padded):
    padnum = ord(padded[-1:])
    unpadded = padded[:-padnum]
    return unpadded


def EncryptCBC(msg, key, iv):
    enc_msg = pad(msg.encode())
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ctext = h(iv)+h(cipher.encrypt(enc_msg))
    return ctext

def DecryptCBC(ctext, key):
    iv = raw(ctext[0:32])
#    print(h(iv))
    ctext_wo_iv = ctext[32:]
 #   print(ctext_wo_iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    msg = unpad(cipher.decrypt(bytes.fromhex(ctext_wo_iv))).decode()
    return msg

class CTR:
    def __init__(self, key):
        self.key = key
        self.count = '0x'+ h(Random.new().read(AES.block_size))
        self.counter = Counter.new(NUM_COUNTER_BITS)
        
    def incCounter(self):
#        print(self.counter)
        intcount = int(self.count,0)
#        print(intcount)
        newcount = intcount+1
        inchiv = hex(newcount)
        if len(inchiv[2:])>32:
            inchiv = '00000000000000000000000000000000'
 #           print('counter overflow')
        self.count = inchiv
 #       print(self.counter)
        return self.count

    def EncryptCTR(self, msg):
        cipher = AES.new(self.key, AES.MODE_ECB)
        cmsg = h(cipher.encrypt(pad(msg.encode())))
        ctext=self.count[2:]
        for i in range(int(len(cmsg)//AES.block_size)):
            block = cmsg[AES.block_size*i:AES.block_size*i+AES.block_size]
            ivi = self.count[2:]
            ctext+=xorb(block,ivi)
            self.incCounter()
        return ctext
    
    def encryptCTR(self, msg):
        cipher =AES.new(self.key, AES.MODE_ECB)
        ctext = self.count[2:]
#        print('iv:', ctext)
        final_block_len = len(msg)%AES.block_size
        numBlocks = len(msg)//AES.block_size
        if final_block_len !=0:
            numBlocks+=1
        for i in range(numBlocks):
            if i==numBlocks:
                chrloops = final_block_len
  #              print('fbl:', final_block_len)
            else: chrloops = AES.block_size
            E = h(cipher.encrypt(bytes.fromhex(self.count[2:])))
            block = ''
            for j in range(chrloops):
                hchar = hex(ord(msg[AES.block_size*i+j:AES.block_size*i+j+1]))[2:]
                char = msg[AES.block_size*i+j:AES.block_size*i+j+1]
                intchar = ord(msg[AES.block_size*i+j:AES.block_size*i+j+1])
  #              print('char:', char, 'int:', intchar, ' hchar:', hchar)
                block+=hchar
  #          print('block:', block)
            ctext += xorb(E, block)
            self.incCounter()
        return ctext
    
    def decryptCTR(self, ctext):
        print()
        iv = ctext[:2*AES.block_size]
 #       print('iv:', iv)
        c = ctext[2*AES.block_size:]
        self.count = '0x' + iv
        cipher = AES.new(self.key,AES.MODE_ECB)
        bmsg=[]
        numBlocks = int(len(c)//(2*AES.block_size))
        if len(c)%AES.block_size!=0:
            numBlocks+=1
#        print('numBlocks:', numBlocks)
        msg=''
        for i in range(numBlocks):
            if i!=numBlocks:
                hexDigits = 2*AES.block_size
            else: hexDigits = len(c)%(2*AES.block_size)
            E = cipher.encrypt(bytes.fromhex(self.count[2:]))
  #          print('E:', E.hex())
            ct = c[AES.block_size*i:AES.block_size*i+hexDigits]
  #          print('ct:', ct)
     #       block=xorb(ct, E)
            xor = XOR.new(bytes.fromhex(ct))
            block = xor.decrypt(E)
            bmsg.append(block)
    #        print('block:', block.hex())
   #         print("block: ", block)
#            blocktext = bytes.fromhex(block)
#            print('blocktext:', blocktext)
            for byte in msg:
#                letter = chr(byte)
#               print('ltr:', letter)
                msg +=byte.decode()
            self.incCounter()
        return msg
 #           print(pt)
  #          cxor = xorb(ctext[32*(i+1):32*(i+2)], self.count[2:])
  #          cmsg_dec=cipher.decrypt(bytes.fromhex(cxor))
   #         cmsg_dec = cipher.decrypt(bytes.fromhex(ctext[32*(i+1):32*(i+2)]))
   #         cxor = xorb(cmsg_dec.hex(), self.count[2:])
   #         for byte in bytes.fromhex(cxor):
  #          for j in range(0, len(block),2):
             
 #               letter = chr(ord(bytes.fromhex(block[j:j+2])))
  #              print("letter:", letter)
 #               msg+=letter
 #               bmsg.append(byte)
#                print((byte), " ", chr(byte))
 #           self.incCounter()
#        msg=''.join(map(chr,bmsg))
#        return msg
       
    
 #   print(ctext_wo_iv)
def test(msg, key):
    ctr = CTR(key)
    ct = ctr.encryptCTR(msg)
    print('ct:', ct)
    dm = ctr.decryptCTR(ct)
    print('dm:', dm)
    return dm

def etest(msg, key):
    ctr = CTR(key)
    return ctr.encryptCTR(msg)

def dtest(msg, key):
    ctr = CTR(key)
    return ctr.decryptCTR(msg)

    # self.secret[self.cnter_cb_called % Cipher.BS] * Cipher.BS

#key = raw(ctlst[0][0])
#ciphertext  = ctlst[0][1]
#iv = raw(ciphertext[0:32])

#print('key:', h(key))
#print('iv:', h(iv))
#msg = 'testing the encryption scheme with a longer message, certainly longer than one block.  Definitely longer than one block'
#print('msg:', iv)
#ctext = Encrypt(msg, key, iv)
#print('encrypted:')
#print(ctext)

#iv_calc = ctext[0:32]
#print('iv_calc:', iv_calc )

# answers to homework
'''
ctext = ctlst[0][1]
print()
print('ciphertext:', ctext)
print()
key = raw(ctlst[0][0])
print('key:')
print(key)
msg1 = DecryptCBC(ctext, key)
print()
print("Answer to Question 1:")
print(msg1)

ctext = ctlst[1][1]
print()
print('ciphertext:', ctext)
key = raw(ctlst[1][0])
print('key:')
print(key)
msg2 = DecryptCBC(ctext, key)
print()
print('Answer to Question 2:')
print(msg2)
'''
def _incCounter(count):
#        print(self.counter)
        intcount = int(count,0)
#        print(intcount)
        newcount = intcount+1
        inchiv = hex(newcount)
        if len(inchiv[2:])>32:
            inchiv = '00000000000000000000000000000000'
 #           print('counter overflow')
        count = inchiv
 #       print(self.counter)
        return count

def _decryptCTR(ctext, key):
 #       print()
        iv = ctext[:2*AES.block_size]
#        print('iv:', iv)
        c = ctext[2*AES.block_size:]
#        print('c:', c)
        count = '0x' + iv
        cipher = AES.new(key,AES.MODE_ECB)
        bmsg=[]
        numBlocks = int(len(c)//(2*AES.block_size))
        if len(c)%AES.block_size!=0:
            numBlocks+=1
#        print('numBlocks:', numBlocks)
        msg=''
        for i in range(numBlocks):
#            print('count:', count[2:])
            if i!=numBlocks-1:
                hexDigits = 2*AES.block_size
                ct = c[2*AES.block_size*i:(2*AES.block_size*i+hexDigits)]
                lastblock = False
            else: 
                hexDigits = len(c)%(2*AES.block_size)
                print('hexDigits:', hexDigits)
                ct = c[2*AES.block_size*i:(2*AES.block_size*i+hexDigits)]
                lastblock = True
   #             for i in range(2*AES.block_size-hexDigits):
    #                ct+='0'
                print('ct:', c[2*AES.block_size*i:(2*AES.block_size*i+hexDigits)])
 #           print('hexDigits:', hexDigits)
            E = cipher.encrypt(bytes.fromhex(count[2:]))
   #         print('E:', E.hex())
            ct = c[2*AES.block_size*i:(2*AES.block_size*i+hexDigits)]
 #           print('ct:', ct)
     #       block=xorb(ct, E)
            xor = XOR.new(bytes.fromhex(ct))
            block = xor.decrypt(E)
 #           print('plain_block:', block)
            if lastblock:
                block = block[:hexDigits//2]
            bmsg.append(block)
    #        print('block:', block.hex())
   #         print("block: ", block)
#            blocktext = bytes.fromhex(block)
#            print('blocktext:', blocktext)
            count = _incCounter(count)
        print(bmsg)
        for byte in bmsg:
#                letter = chr(byte)
#               print('ltr:', letter)
            try:
                msg +=byte.decode()
            except:
                pass
#            print(byte.decode())
            
        print(msg)
        return msg

#ctext = ctlst[1][1]
#key = raw(ctlst[1][0])
#ctr = CTR(key)
#msg3 = _decryptCTR(ctext, key)
#print(msg3)

ctext = ctlst[2][1]
key = raw(ctlst[2][0])
#ctr = CTR(key)
msg4 = _decryptCTR(ctext, key)
print(msg4)
#print()
#print('Answer to Question 3:')
#print(msg3)



#ciphertext  = ctlst[0][1]
#iv = raw(ciphertext[0:32])
#padding = ciphertext[-2:]
#ctext = ciphertext[33:]

#iv_plus_ciphertext = iv + cipher.encrypt(pad(b'Attack at dawn'))
#decipher = AES.new(key, AES.MODE_CBC, iv)

#cipher = AES.new(key, AES.MODE_CBC, iv)
#test = b'this a message'
#(msg = cipher.encrypt(test)


#msg = cipherCTR.encrypt(b'test')

#ciphertext = b''
#for byte in range(2, len(iv_plus_ciphertext)):
#    ciphertext+=byte

#key = b'Sixteen byte key'
#iv = Random.new().read(AES.block_size)
#cipher = AES.new(key, AES.MODE_CBC, iv)
#cipherCTR = AES.new(key,AES.MODE_CTR)

#pickIV = Random.new().read(AES.block_size)    

class IVCounter(object):
    def __init__(self, start=1):
        self.value = long(start)

    def __call__(self):
        self.value += 1
        return hex(self.value)[2:34]

def decryptCTR(key, ciphertext):
    iv = ciphertext[:32] #extracts the first 32 characters of the ciphertext
    iv = array.array('B', iv.decode("hex")).tostring()

    ciphertext = ciphertext[32:]

    #convert the key into a 16 byte string
    key = array.array('B', key.decode("hex")).tostring()

    #ctr = IVCounter(long(iv))
    ctr = Crypto.Util.Counter.new(16, iv)

    print (AES.new(key, AES.MODE_CTR).decrypt(ciphertext))
    return