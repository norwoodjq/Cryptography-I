# -*- coding: utf-8 -*-
"""
Created on Sat Aug  5 10:37:53 2017

@author: John
"""
import urllib.request
import urllib.error
import urllib.response
import sys
from Crypto.Cipher import AES
from Crypto import Random

mprime0 = 'Pay Bob 500$'
m0 = 'Pay Bob 100$'
mp0h = mprime0.encode().hex()
m0h = m0.encode().hex()
c0h = '20814804c1767293b99f1d9cab3bc3e7ac1e37bfb15599e5f40eef805488281d'
key = bytes.fromhex("140b41b22a29beb4061bda66b6747e14")

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



ivh = c0h[:32]
dkc0 = xorb(ivh, m0h)
ivph = xorb(dkc0,mp0h)
cp = xorb(dkc0, ivph)


letters = b' etaonhisrdlu\nwmycgf,bp.vk"I\'-T;HMWA_SB?x!jEzCqLDYJNO:PRGFKVUXQ)(0*128453679Z&][$/+@#%<=>\\^`{|}~'
customer_data = 'f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4'

TARGET = 'http://crypto-class.appspot.com/po?er='
#--------------------------------------------------------------
# padding oracle
#--------------------------------------------------------------
class PaddingOracle(object):
    def query(self, q):
        target = TARGET + urllib.request.quote(q)    # Create query URL
        req = urllib.request.Request(target)         # Send HTTP request to server
        try:
            f = urllib.request.urlopen(req)          # Wait for response
        except urllib.request.HTTPError as e:          
            print ("We got: %d" % e.code )      # Print response code
            if e.code == 404:
                return True # good padding
            return False # bad padding
        print('valid url, code:', f)

#if __name__ == "__main__":
po = PaddingOracle()
#po.query(sys.argv[1])       # Issue HTTP query with the given argument

# lastbyte xor g xor 0x01         
        
import urllib3

http = urllib3.PoolManager(10)
TARGET = 'http://crypto-class.appspot.com/po?er='

def oracle(q):	#input hex text, returns status code
	target = TARGET + q                         # Create query URL
	r = http.request('GET', target)
	return r.status              # Valid pad if status = 404

ct = (
	'f20bdba6ff29eed7b046d1df9fb70000'
	'58b1ffb4210a580f748b4ac714c001bd'
	'4a61044426fb515dad3f21f18aa577c0'
	'bdf302936266926ff37dbf7035d5eeb4'	# All 4 blocks of PA4
)

print('Padding OK,  Message OK:\t',oracle(ct))

ct = (
	'f20bdba6ff29eed7b046d1df9fb70000'
	'58b1ffb4210a580f748b4ac714c001bd'
	'4a61044426fb515dad3f21f18aa577c0'
	'bdf302936266926ff37dbf7035d5eeb5' #<-------last byte altered
)

print('Message ??, Padding Bad:\t',oracle(ct))

ct = (
	'4a61044426fb515dad3f21f18aa577c0'
	'bdf302936266926ff37dbf7035d5eeb4'	# Last 2 blocks of PA4
)

print('Message bad, Padding OK:\t',oracle(ct))

ct = (
	'This is just messed up'	# This is not hex
)

print('Server says please use "hex":\t',oracle(ct))

ct = '123'				#this is almost hex, but not

print('Server says somethings wrong:\t',oracle(ct))

c0 = 'f20bdba6ff29eed7b046d1df9fb70000'
c1 = '58b1ffb4210a580f748b4ac714c001bd'
c2 = '4a61044426fb515dad3f21f18aa577c0'
c3 = 'bdf302936266926ff37dbf7035d5eeb4'

def findlastbyte():
    m = [0]*16
    mh = ''
    loops = int(len(letters.hex())/2)
    for i in range(16):        
#        print(letters.hex())
        for j in range(loops):
            g = letters.hex()[2*j:(2*j+2)]
            rawg = bytes.fromhex(g)
            rawi = bytes([i])
            gxorpad = bytes(x^y for x,y in zip(rawg,rawi))
#        print(gxorpad)
            cdbyte = customer_data[-2*(i+1):len(customer_data)-2*i]
 #           print (cdbyte)
            rawc = bytes.fromhex(cdbyte)
  #          print(rawc)
            last = bytes(x^y for x,y in zip(gxorpad,rawc))
            test = customer_data[:-2]+last.hex()
#        print(test)
            if oracle(test)==404:
                print(rawg.decode(), '\t', chr(letters[j]) )
                break;
                
knownct1 = 'ed2decd3e2f66b653257f4688c20a6e0c41d0463064876b3c8594eb93bd9bc04badb01badb01badb01badb01badb01ba'
k1c0 = knownct1[:32]
k1c1 = knownct1[32:64]
k1c2 = knownct1[64:]
knownm1= 'murphy is admin   seems legit\x03\x03\x03'
knownct2 = 'c0f8238019ca7ac2bb0488b2e5d83174147ac6aa732544a1066525583405424ff005ba11f005ba11f005ba11f005ba11'
knownm2 = 'All your base are belong to us\02\02'
k2c0 = knownct2[:32]
k2c1 = knownct2[32:64]
k2c2 = knownct2[64:]
                
def decryptBlock(iv, c):
    print('c:           ', iv,  c)
    m = [0]*16
    pt = ['*']*16
    cprime = [0]*16
#    loops = int(len(letters.hex())/2)
    rawiv = bytes.fromhex(iv)
    for i in range(0,16,1):
        rawpos = bytes([i+1])
  #      print('pad:', rawpos.hex())
        for k in range(0, i, 1):
            # c0'[15] = 0x03 xor 's' xor c0[15]
            # c0'[14] = 0x03 xor 'O' xor c0[14]
            # c0'[13] = 0x03 xor g xor c0[13]
            cp = bytes(x^y for x,y in zip(bytes([rawiv[15-k]]),rawpos))
 #           print('k:', k,'  rawiv[15-k] xor with pad:', cp, '  m[15-k]:', bytes(m[15-k]))
            cprime[15-k]=bytes(x^y for x,y in zip(bytes(m[15-k]), cp))
 #           print('cprime[15-k]:',cprime[15-k].hex())
        found = False
        for j in range(len(letters)):
 #           g = letters.hex()[2*j:(2*j+2)]   #guesses: scroll through letters converted to hex
            rawg = bytes([letters[j]])
 #           rawg = bytes.fromhex(g)       # convert to bytes for xor
            gxorpad = bytes(x^y for x,y in zip(rawg,rawpos))
 #           print('guess letter:', chr(ord(rawg)), '\t rawg:', rawg, 'rawpos', rawpos ,'gXORpad:', gxorpad)
            cp = bytes(x^y for x,y in zip(bytes([rawiv[15-i]]),gxorpad))
 #           print('rawiv{15-i}:', bytes([rawiv[15-i]]), ' xor with gXORpad => substitution:', cp.hex())
            test = iv[:32-2*(i+1)]+cp.hex()
            for n in range((16-i),16,1):
                test+=cprime[n].hex()
            if j==0: 
  #              print('cprime:', cprime)
    #            print('first guess')
    #            print('oracle input:', test, c)
    #            print('searching...')
      #          print('n:', n, 'cprime[15-n].hex():', cprime[15-n].hex())
            test+=c
            result = oracle(test)
  #          print('oracle output:', result)
            if result==404:
                found=True
                m[15-i]=bytes([letters[j]])
                pt[15-i]=chr(letters[j])
    #            print('oracle returned 404')
                print('m:', pt)
                break;
        if not found: print('none found')
     #   return
                           
 #           c0'[15] = 0x01 xor 's' xor c0[15]
        
    
def decryptLastBlock(iv, c, pad):
    print('c:           ', iv,  c)
    m = [0]*16
    pt = ['*']*16
    cprime = [0]*16
#    for i in range(pad):
 #       cprime[15-i]=bytes([pad])
 #       m[15-i] = bytes([pad])
#    loops = int(len(letters.hex())/2)
    rawiv = bytes.fromhex(iv)   # inialiazation vector in bytes
    for i in range(1,16,1):   # may need to start i with 1
        rawpos = bytes([i+1]) # 
        print('pad:', rawpos.hex())
        for k in range(0, i, 1):
            # c0'[15] = 0x03 xor 's' xor c0[15]
            # c0'[14] = 0x03 xor 'O' xor c0[14]
            # c0'[13] = 0x03 xor g xor c0[13]
            if k>pad-1:         # may need to use k>pad-2:
                cp = bytes(x^y for x,y in zip(bytes([rawiv[15-k]]),rawpos))
            else: 
                cp = bytes([pad])
                m[15-k] = pad
            print('k:', k, 'rawiv[15-k]:', bytes([rawiv[15-k]]),'  rawiv[15-k] xor with pad:', cp, '  m[15-k]:', bytes(m[15-k]))
            if k>pad-1:
                cprime[15-k]=bytes(x^y for x,y in zip(bytes(m[15-k]), cp))  
            else:
                cprime[15-k]= bytes(x^y for x,y in zip(bytes([rawiv[15-k]]),bytes([pad])))
            print('cprime[15-k]:',cprime[15-k].hex())
        found = False
        for j in range(len(letters)):
 #           g = letters.hex()[2*j:(2*j+2)]   #guesses: scroll through letters converted to hex
            rawg = bytes([letters[j]])
 #           rawg = bytes.fromhex(g)       # convert to bytes for xor
            gxorpad = bytes(x^y for x,y in zip(rawg,rawpos))
 #           print('guess letter:', chr(ord(rawg)), '\t rawg:', rawg, 'rawpos', rawpos ,'gXORpad:', gxorpad)
            cp = bytes(x^y for x,y in zip(bytes([rawiv[15-i]]),gxorpad))
 #           print('rawiv{15-i}:', bytes([rawiv[15-i]]), ' xor with gXORpad => substitution:', cp.hex())
            test = iv[:32-2*(i+1)]+cp.hex()
            for n in range((16-i),16,1):
                test+=cprime[n].hex()
            if j==0: 
  #              print('cprime:', cprime)
                print('first guess')
                print('oracle input:', test, c)
                print('searching...')
      #          print('n:', n, 'cprime[15-n].hex():', cprime[15-n].hex())
            test+=c
            result = oracle(test)
  #          print('oracle output:', result)
            if result==404:
                found=True
                m[15-i]=bytes([letters[j]])
                pt[15-i]=chr(letters[j])
                print('oracle returned 404')
                print('m:', pt)
                break;
        if not found: print('none found')
        
def decryptLastBlock2(iv, c):
    print('c:           ', iv,  c)
    m = [0]*16
    m[15]= b'\02'
    m[14]= b'\02'
    pt = ['*']*16
    cprime = [0]*16
#    loops = int(len(letters.hex())/2)
    rawiv = bytes.fromhex(iv)
    for i in range(2,16,1):
        rawpos = bytes([i+1])
        print('pad:', rawpos.hex())
        for k in range(0, i, 1):
            # c0'[15] = 0x03 xor 's' xor c0[15]
            # c0'[14] = 0x03 xor 'O' xor c0[14]
            # c0'[13] = 0x03 xor g xor c0[13]
            cp = bytes(x^y for x,y in zip(bytes([rawiv[15-k]]),rawpos))
            print('k:', k,'  rawiv[15-k] xor with pad:', cp, '  m[15-k]:', bytes(m[15-k]))
            cprime[15-k]=bytes(x^y for x,y in zip(bytes(m[15-k]), cp))
            print('cprime[15-k]:',cprime[15-k].hex())
        found = False
        for j in range(len(letters)):
 #           g = letters.hex()[2*j:(2*j+2)]   #guesses: scroll through letters converted to hex
            rawg = bytes([letters[j]])
 #           rawg = bytes.fromhex(g)       # convert to bytes for xor
            gxorpad = bytes(x^y for x,y in zip(rawg,rawpos))
    #        print('guess letter:', chr(ord(rawg)), '\t rawg:', rawg, 'rawpos', rawpos ,'gXORpad:', gxorpad)
            cp = bytes(x^y for x,y in zip(bytes([rawiv[15-i]]),gxorpad))
    #        print('rawiv{15-i}:', bytes([rawiv[15-i]]), ' xor with gXORpad => substitution:', cp.hex())
            test = iv[:32-2*(i+1)]+cp.hex()
            for n in range((16-i),16,1):
                test+=cprime[n].hex()
            if j==0: 
  #              print('cprime:', cprime)
                print('first guess')
                print('oracle input:', test, c)
                print('searching...')
      #          print('n:', n, 'cprime[15-n].hex():', cprime[15-n].hex())
   #         print('oracle input:', test, c)      
            test+=c
            result = oracle(test)
  #          print('oracle output:', result)
            if result==404:
                found=True
                m[15-i]=bytes([letters[j]])
                pt[15-i]=chr(letters[j])
                print('oracle returned 404')
                print('m:', pt)
                break;
        if not found: print('none found')
        
def decryptLastBlock3(iv, c):
    print('c:           ', iv,  c)
    m = [0]*16
    m[15]= b'\03'
    m[14]= b'\03'
    m[13]= b'\03'
    pt = ['*']*16
    cprime = [0]*16
#    loops = int(len(letters.hex())/2)
    rawiv = bytes.fromhex(iv)
    for i in range(3,16,1):
        rawpos = bytes([i+1])
        print('pad:', rawpos.hex())
        for k in range(0, i, 1):
            # c0'[15] = 0x03 xor 's' xor c0[15]
            # c0'[14] = 0x03 xor 'O' xor c0[14]
            # c0'[13] = 0x03 xor g xor c0[13]
            cp = bytes(x^y for x,y in zip(bytes([rawiv[15-k]]),rawpos))
            print('k:', k,'  rawiv[15-k] xor with pad:', cp, '  m[15-k]:', bytes(m[15-k]))
            cprime[15-k]=bytes(x^y for x,y in zip(bytes(m[15-k]), cp))
            print('cprime[15-k]:',cprime[15-k].hex())
        found = False
        for j in range(len(letters)):
 #           g = letters.hex()[2*j:(2*j+2)]   #guesses: scroll through letters converted to hex
            rawg = bytes([letters[j]])
 #           rawg = bytes.fromhex(g)       # convert to bytes for xor
            gxorpad = bytes(x^y for x,y in zip(rawg,rawpos))
    #        print('guess letter:', chr(ord(rawg)), '\t rawg:', rawg, 'rawpos', rawpos ,'gXORpad:', gxorpad)
            cp = bytes(x^y for x,y in zip(bytes([rawiv[15-i]]),gxorpad))
    #        print('rawiv{15-i}:', bytes([rawiv[15-i]]), ' xor with gXORpad => substitution:', cp.hex())
            test = iv[:32-2*(i+1)]+cp.hex()
            for n in range((16-i),16,1):
                test+=cprime[n].hex()
            if j==0: 
  #              print('cprime:', cprime)
                print('first guess')
                print('oracle input:', test, c)
                print('searching...')
      #          print('n:', n, 'cprime[15-n].hex():', cprime[15-n].hex())
   #         print('oracle input:', test, c)      
            test+=c
            result = oracle(test)
  #          print('oracle output:', result)
            if result==404:
                found=True
                m[15-i]=bytes([letters[j]])
                pt[15-i]=chr(letters[j])
                print('oracle returned 404')
                print('m:', pt)
                break;
        if not found: print('none found')
        
def decryptLastBlockPad(iv, c, pad):
    print('c:           ', iv,  c)
    m = [0]*16
    for i in range(pad):
        m[15-i]=bytes([pad])
    pt = ['*']*16
    cprime = [0]*16
#    loops = int(len(letters.hex())/2)
    rawiv = bytes.fromhex(iv)
    for i in range(pad,16,1):
        rawpos = bytes([i+1])
        print('pad:', rawpos.hex())
        for k in range(0, i, 1):
            # c0'[15] = 0x03 xor 's' xor c0[15]
            # c0'[14] = 0x03 xor 'O' xor c0[14]
            # c0'[13] = 0x03 xor g xor c0[13]
            cp = bytes(x^y for x,y in zip(bytes([rawiv[15-k]]),rawpos))
            print('k:', k,'  rawiv[15-k] xor with pad:', cp, '  m[15-k]:', bytes(m[15-k]))
            cprime[15-k]=bytes(x^y for x,y in zip(bytes(m[15-k]), cp))
            print('cprime[15-k]:',cprime[15-k].hex())
        found = False
        for j in range(len(letters)):
 #           g = letters.hex()[2*j:(2*j+2)]   #guesses: scroll through letters converted to hex
            rawg = bytes([letters[j]])
 #           rawg = bytes.fromhex(g)       # convert to bytes for xor
            gxorpad = bytes(x^y for x,y in zip(rawg,rawpos))
    #        print('guess letter:', chr(ord(rawg)), '\t rawg:', rawg, 'rawpos', rawpos ,'gXORpad:', gxorpad)
            cp = bytes(x^y for x,y in zip(bytes([rawiv[15-i]]),gxorpad))
    #        print('rawiv{15-i}:', bytes([rawiv[15-i]]), ' xor with gXORpad => substitution:', cp.hex())
            test = iv[:32-2*(i+1)]+cp.hex()
            for n in range((16-i),16,1):
                test+=cprime[n].hex()
            if j==0: 
  #              print('cprime:', cprime)
                print('first guess')
                print('oracle input:', test, c)
                print('searching...')
      #          print('n:', n, 'cprime[15-n].hex():', cprime[15-n].hex())
   #         print('oracle input:', test, c)      
            test+=c
            result = oracle(test)
  #          print('oracle output:', result)
            if result==404:
                found=True
                m[15-i]=bytes([letters[j]])
                pt[15-i]=chr(letters[j])
                print('oracle returned 404')
                print('m:', pt)
                break;
        if not found: print('none found')
        