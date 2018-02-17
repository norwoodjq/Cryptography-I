# -*- coding: utf-8 -*-
"""
Created on Sat Aug 12 00:19:37 2017

@author: John
"""
import gmpy2
from gmpy2 import mpz

#In[1]:=  PrimeQ[1073676287] (*this is prime*)
#Out[1]= True
p1=gmpy2.mpz(1073676287)
g1=gmpy2.mpz(1010343267)
h1=gmpy2.mpz(857348958)
B=2**20
#x = MultiplicativeOrder[g,p,h]
 #       x < 2^20
# Out[6]= 1026831 (*this is the solution*)
# Out[7]= True
# in[8]:= x0 = 1002; (from pa5)
#        x1 = 783;
#        Mod[h PowerMod[g,-x1,p],p]  (*left hand side*)
#        PowerMod[g,(x0 B),p]        (*right hand side*)
#Out[10]= 658308031
#Out[11]= 658308031
 
p = gmpy2.mpz(13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171)
g = gmpy2.mpz(11717829880366207009516117596335367088558084999998952205599979459063929499736583746670572176471460312928594829675428279466566527115212748467589894601965568) 
h = gmpy2.mpz(3239475104050450443565264378728065788649097520952449527834792452971981976143292558073856937958553180532878928001494706097394108577585732452307673444020333)
    

def assg5(p, g, h):

# find x such that h = g**x in Zp
# use gmpy2 or numbthy modules to support multi-precision modular arithmetic
#
# B=2**20
# x=x0*B+x1           x0, x1 in range [0,B-1]
# h/g**x1 = (g**B)**x0   in Zp
#
# first build a hash table of all possible values of the left hand side h/g**x1 for
#   x1=0,1...2**20
# for each value x0 = 0,1,2...2**20 test to see if (g**B)**x0 is in the hash table
#   if true, calc x as x0*B+x1

# note that all calcs need to be done in mod P

    LHS = {}
    numinv = 0
    numnon = 0
    print('building lookup table...')
    for x1 in range(B):
        gtox=gmpy2.powmod(g,x0,p)
        try:
            invx = gmpy2.invert(gtox,p)
        #    print('invx:', invx)
            numinv+=1
            entry =gmpy2.f_mod(h*invx,p)
#            entry = gmpy2.f_mod(gmpy2.mul(h,invx), p)
            if entry == 1:
                print('x0:', x0, ' invx:', invx)
            LHS[entry] = x0
        #    print('LHS[x]:', LHS[x])
        except:         
            numnon+=1  
    print('searching for x...')
    for x0 in range(B):
        RHS = gmpy2.f_mod(gmpy2.powmod(gmpy2.powmod(g,B,p),x1,p),p)
#        print('RHS:', RHS)
        if RHS in LHS:
            x1 = LHS[RHS]  
            x = x0*B+x1
 #           xmod = (((357984 * 2**20) + 787046)% p)
            rv = gmpy2.f_mod(x,p)
            print('x0:', x0,' x1:', x1, ' RHS:', RHS, ' returns:', rv)
            return (rv,LHS)
    print('no match')
    return(None)
