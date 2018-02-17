# -*- coding: utf-8 -*-
"""
Created on Sun Jul 30 16:54:26 2017

@author: John
"""
#import sys
#import re
#from Crypto import *
import hashlib

h0 = '03c08f4ee0b576fe319338139c045c89c3e8e9409633bea29442e21425006ea8'

def createfiles():
    rawhex1 = b'\x11'*1024
    rawhex2 = b'\x22'*1024
    rawhex3 = b'\x33'*1024
    rawhex4 = b'\x44'*773
    e1 = open('b1','wb')
    e2 = open('b2','wb')
    e3 = open('b3','wb')
    e4 = open('b4','wb')
    t1 = open('small_test','wb')
    e1.write(rawhex1)
    e2.write(rawhex2)
    e3.write(rawhex3)
    e4.write(rawhex4)
    h3 = bytes.fromhex(hashlib.sha256(rawhex4).hexdigest())
    h2 = bytes.fromhex(hashlib.sha256(rawhex3+h3).hexdigest())
    h1 = bytes.fromhex(hashlib.sha256(rawhex2+h2).hexdigest())
 #   h0 = hashlib.sha256(rawhex1+h1)
    t1.write(rawhex1+h1+rawhex2+h2+rawhex3+h3+rawhex4)
    t1.close()
    e1.close()
    e2.close()
    e3.close()
    e4.close()
    
def createfiles2():
    rawhex1 = b'\x11'*1024
    rawhex2 = b'\x22'*1024
    rawhex3 = b'\x33'*1024
    rawhex4 = b'\x44'*773
    e1 = open('b1','wb')
    e2 = open('b2','wb')
    e3 = open('b3','wb')
    e4 = open('b4','wb')
    t1 = open('small_test2','wb')
    e1.write(rawhex1)
    e2.write(rawhex2)
    e3.write(rawhex3)
    e4.write(rawhex4)
    h3 = bytes.fromhex(hashlib.sha256(rawhex4).hexdigest())
    h2 = bytes.fromhex(hashlib.sha256(rawhex3+h3).hexdigest())
    h1 = bytes.fromhex(hashlib.sha256(rawhex2+h2).hexdigest())
 #   h0 = hashlib.sha256(rawhex1+h1)
    t1.write(rawhex1+rawhex2+rawhex3+rawhex4)
    t1.close()
    e1.close()
    e2.close()
    e3.close()
    e4.close()

# b4 hash d8f8a9eadd284c4dbd94af448fefb24940251e75ca2943df31f7cfbb6a4f97ed
# b3 hash 26949e3320c315f179e2dfc95a4158dcf9a9f6ebf3dfc69252cd83ad274eeafa
# b2 hash 946e42c2bd9cbb56dcbefe0eea7ad361e18a4a052421b088b8050b1ba99795ff
# b1 hash af7aca38c840da949c02a57e1c31d48ab7a1b9c7486638a892f2409770ec3ae5

def catWords(word1, word2):
    return word1+word2

def fileopentest():
    with open('test_mp4', 'rb') as f:
        block1=''
        word1=''
        block2=''
        word2=''
        for i in range(1024):
            byte = f.read(1).hex()
            if not byte:
                print('error in genesis block')
            block1+=byte
        for i in range(32):
            byte= f.read(1).hex()
            if not byte:
                print('no more bytes for word1')
                word1+=byte
        for i in range(1024):
            byte = f.read(1).hex()
            if not byte:
                print('error in block 2')
                block2+=byte
        for i in range(32):
            byte= f.read(1).hex()
            if not byte:
                print('no more bytes for word2')
                word2+=byte
        hashedWord1 = hashlib.sha256(bytes.fromhex(block1)).hexdigest()
        hashedWord2 = hashlib.sha256(bytes.fromhex(word1+block2)).hexdigest()
        print('block1')
        print(block1)
        print('word1')
        print(word1)
        print('hashedWord1')
        print(hashedWord1)
        print('block2')
        print(block2)
        print('word2')
        print(word2)
        print('hashedWord2')
        print(hashedWord2)
        
def fileopentest3():
    with open('test_mp4', 'rb') as f:
        block0=f.read(1024)
        h1=f.read(32)
        block1=f.read(1024)
        h2=f.read(32)
        h0calc = hashlib.sha256(block0+h1).hexdigest()
        hashedWord1 = hashlib.sha256(block1).hexdigest()
#        hashedWord2 = hashlib.sha256(word1+block2).hexdigest()
        print('h0')
        print(h0)
        print('h0calc')
        print('block0')
        print(block0.hex())
        print('h1')
        print(h1.hex())

        
        
    
def fileopentest2():
    with open('test_mp4', 'rb') as f:
        block1=f.read(1024)
        word1=f.read(32)
        block2=f.read(1024)
        word2=f.read(32)
        hashedWord1 = hashlib.sha256(block1).hexdigest()
        hashedWord2 = hashlib.sha256(word1+block2).hexdigest()
        print('block1')
        print(block1.hex())
        print('word1')
        print(word1.hex())
        print('hashedWord1')
        print(hashedWord1)
        print('block2')
        print(block2.hex())
        print('word2')
        print(word2.hex())
        print('hashedWord2')
        print(hashedWord2)
        
def fileopentest4(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    lastblocklen = len(data)%(1024)
#    print(lastblocklen)
    fullblocks = data[:len(data)-lastblocklen]
 #           print(fullblocks)
    index = len(data)-lastblocklen
    lastblock = data[index:]
    print(len(lastblock))
 #           print(lastblock.hex())
    h = hashlib.sha256(lastblock).hexdigest()
    print(h)
    for i in range(int(len(fullblocks)/1024)):
        index = index-1024
        thisblock = data[index:index+1024]
        h = hashlib.sha256(bytes.fromhex(thisblock.hex()+h)).hexdigest()
#        print(len(thisblock))
        print(h)
  #          numblocks = len(fullblocks)/1024
            
            
def calch0():
    with open('test_mp4', 'rb') as f:
        data = f.read()
    block0 = data[:1024]
    h1 = data[1024:1024+32] 
    h0 = hashlib.sha256(block0+h1).hexdigest()
    print(h0)
    
        

def main():
    done = False
    counter = 0
    with open('test_mp4', 'rb') as f:
        block = ''
        word = ''
        for i in range(1024):
            byte = f.read(1).hex()
            if not byte:
                    print('error in genesis block')
                    break
            block+=byte
        while not done:
            if counter>10:
                done = True
            hashedWord = hashlib.sha256(bytes.fromhex(word+block))
            print('hashed word')
            print(hashedWord)
            for i in range(32):
                byte= f.read(1).hex()
                if not byte:
                    print('no more bytes for word')
                    done = True
                    break
                word+=byte
            if hashedWord != word:
                print('invalid hash')
                print('word')
                print(word)
            else:
                print(' valid block!!!!!!!!!!!')
            word = ''
            for i in range(1024):
                byte = f.read(1).hex()
                if not byte:
                    done = True
                    print('no more bytes for block')
                    break
                block+=byte
            counter+=1
   #         print(i)
    
    
#var = 'password'
#hashedWord = sha256(b var).hexdigest()
#hashedWord2 = sha256(var.encode('ascii')).hexdigest()
#print(hashedWord)
        


  # For each filename, get the names, then either print the text output
  # or write it to a summary file
  
if __name__ == '__main__':
  main()