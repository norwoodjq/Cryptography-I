# -*- coding: utf-8 -*-
"""
Created on Sun Jul 16 21:29:39 2017

@author: John
"""

#import sys
import random
import binascii

MSGS = ( "hello world", "testing, 1,2,3...", "attack at dawn", "attack at dusk")

def strxor(a, b):     # xor two strings of different lengths
    if len(a) > len(b):
       return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
       return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

#def random(size=16):
#    return open("/dev/urandom").read(size)

def encrypt(key, msg):
    c = strxor(key, msg)
    print ("Printing")   
    print (binascii.hexlify(b 'c'))
    return c
    
# def decrypt()

def main():
    key = str(random.getrandbits(1024))
    ciphertexts = [encrypt(key, msg) for msg in MSGS]
    return ciphertexts
    
    