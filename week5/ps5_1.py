# -*- coding: utf-8 -*-
"""
Created on Sat Aug 12 01:28:39 2017

@author: John
"""
import gmpy2

#In[1]:=  PrimeQ[1073676287] (*this is prime*)
#Out[1]= True
p1=1073676287;
g1=1010343267;
h1=857348958;
B=2^10;
x = MultiplicativeOrder[g,p,h]
 #       x < 2^20
# Out[6]= 1026831 (*this is the solution*)
# Out[7]= True
# In[8]:= x0 = 1002;    (* from pa5.py *)
#        x1 = 783;
#        Mod[h PowerMod[g,-x1,p],p]  (*left hand side*)
#        PowerMod[g,(x0 B),p]        (*right hand side*)
#Out[10]= 658308031
#Out[11]= 658308031

p = 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171
g = 11717829880366207009516117596335367088558084999998952205599979459063929499736583746670572176471460312928594829675428279466566527115212748467589894601965568 
h = 3239475104050450443565264378728065788649097520952449527834792452971981976143292558073856937958553180532878928001494706097394108577585732452307673444020333
    
B = 2**20

def MultiplicativeOrder(p, g, h):

# find x such that h = g**x in Zp
# use gmpy2 or numbthy modules to support multi-precision modular arithmetic
#
# B=2**20
# x=x0*B+x1           x0, x1 in range [0,B-1]
# h/g**x1 = (g**B)**x0   in Zp
#
# first build a hash table of all possible values of the left hand side h/g^x1 for
#   x1=0,1...2**20
# for each value x0 = 0,1,2...2**20 test to see if (g**B)**x0 is in the hash table
#   if true, calc x as x0*B+x1

# note that all calcs need to be done in mod P

    LHS = {}
    xinverse = invert(x,p)
    for x in range(B):
        LHS[x] = h/(g**x)   # this will actually be h*g**-x
        RHS = (g**B)**x
        if (RHS in LHS):
            return RHS**B+x