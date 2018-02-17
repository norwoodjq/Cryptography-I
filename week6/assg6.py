# -*- coding: utf-8 -*-
"""
Created on Sun Aug 13 00:00:00 2017

@author: John
"""

import gmpy2
gmpy2.get_context().precision=2048

# PROBLEM 1

#from gmpy2 import mpz

# The following modulus N is a products of two primes p and q where 
# |p−q|<2N**.25. Find the smaller of the two factors and enter it as a 
# decimal integer in the box below.
 
 
N = gmpy2.mpz(179769313486231590772930519078902473361797697894230657273430081157732675805505620686985379449212982959585501387537164015710139858647833778606925583497541085196591615128057575940752635007475935288710823649949940771895617054361149474865046711015101563940680527540071584560878577663743040086340742855278549092581)
       
# Let A be the arithmetic average of the two primes, that is A=p+q2. Since 
# p and q are odd, we know that p+q is even and therefore A is an integer.

# To factor N you first observe that under condition |p−q|<2N**.25 the quantity 
# (N)**.5 is very close to A. In particular, we show below that: A−(N)**.5<1

# But since A is an integer, rounding (N)**.5 up to the closest integer reveals 
# the value of A. In code, A=ceil(sqrt(N)) where "ceil" is the ceiling function.


def factors1(n):
    rootN = gmpy2.sqrt(n)
    A = gmpy2.ceil(rootN)
 #   rootNsq = rootN**2
 #   Ncalc = N-rootNsq
#    res1 = gmpy2.mpz(A**2-N)
    x = gmpy2.sqrt(A**2-N)
    p = A-x
    q = A+x
    return (int(p),int(q))

def fac3(N):
    root6N = 2*gmpy2.sqrt(6*N)
    Ax2 = gmpy2.ceil(root6N)
    A = Ax2/2
    x = gmpy2.sqrt(A**2-6*N)
    p = (A-x)/3
    q = (A+x)/2
    print('p:\n'+ str(int(p)))
    print('q:\n'+ str(int(q)))
    return (int(p), int(q))

rootN = gmpy2.sqrt(N)
#print('rootN:', rootN)
#A = gmpy2.ceil(gmpy2.sqrt(N))
A = gmpy2.ceil(rootN)
rootNsq = rootN**2
Ncalc = N-rootNsq
#print('A:', A, 'A>N:', A>N, 'A>rootN:', A>rootN, 'Ncalc:', Ncalc)

# Since A is the exact mid-point between p and q there is an integer x 
# such that p=A−x and q=A+x.

# But then N=pq=(A−x)(A+x)=A2−x2 and therefore x=A2−N**.5

res1 = gmpy2.mpz(A**2-N)
#print('res1:', res1)



x = gmpy2.sqrt(A**2-N)
#print('x:', x)
# Now, given x and A you can find the factors p and q of N since p=A−x and q=A+x. 
# You have now factored N  

p = int(A-x)
q = int(A+x)
print('')
print('')
print('problem 1')
print('p:', p)
print('q:', q)
#phi = (1-1/p)*(1-1/q)*N
phi = (p-1)*(q-1)
#print('phi:', int(phi))

# PROBLEM 2
#N2check=648455842808071669662824265346772278726343720706976263060439070378797308618081116462714015276061417569195587321840254520655424906719892428844841839353281972988531310511738648965962582821502504990264452100885281673303711142296421027840289307657458645233683357077834689715838646088239640236866252211790085787877
N2=648455842808071669662824265346772278726343720706976263060439070378797308618081116462714015276061417569195587321840254520655424906719892428844841839353281972988531310511738648965962582821502504990264452100885281673303711142296421027840289307657458645233683357077834689715838646088239640236866252211790085787877
N3=720062263747350425279564435525583738338084451473999841826653057981916355690188337790423408664187663938485175264994017897083524079135686877441155132015188279331812309091996246361896836573643119174094961348524639707885238799396839230364676670221627018353299443241192173812729276147530748597302192751375739387929


#print('problem 2 solution:')
'''
guess = int(gmpy2.floor(gmpy2.sqrt(N2)))
print('guess:')
print(guess)
#print('N2/guess:\n'+ str(int(N2/guess)) + '\nN2%guess:\n'+ str(int(N2%guess)))
for i in range(2**20):
    guess+=i
    if N2%guess<1000:
        print('p:', int(guess))
        print('q:', int(N2/guess))
 #       break
print('final guess:')
print(guess)
print('done')
'''

def factors(n):
    result = set()
    n = gmpy2.mpz(n)
    start = gmpy2.isqrt(n)
    end = start+2**22
    for i in range(start, end):
        div, mod = divmod(n, i)
        if not mod:
            result |= {gmpy2.mpz(i), div}
    return result

def factors2(n):
    n = gmpy2.mpz(n)
    init_guess = gmpy2.isqrt(n)
    A=init_guess
#    print('intial guess:')
#    print(guess)
    #print('N2/guess:\n'+ str(int(N2/guess)) + '\nN2%guess:\n'+ str(int(N2%guess)))
    mindiv = n
    for i in range(1048576):
        x = gmpy2.sqrt(A**2-n)
        p=A-x
        q=A+x
        mod = gmpy2.fmod(n,p) 
        div = gmpy2.div(n,p*q)
        if div<mindiv:
            mindiv = div
        if not mod:
            print('p:\n'+str(int(p)))
            print('q:\n'+str(int(q)))
            break
        A+=1
#    print('final guess:')
#    print(guess)
#    print('minmod:', minmod)
#    print(2**20)
#    rootN = gmpy2.sqrt(n)
#    A = gmpy2.ceil(rootN)
 #   rootNsq = rootN**2
 #   Ncalc = N-rootNsq
#    res1 = gmpy2.mpz(A**2-N)
#    x = gmpy2.sqrt(A**2-N)
#    p = A-x
#    q = A+x
#    return (int(p),int(q))
 
testp3 = 1166083
testq3 = 1749149
testN3 = 2039652913367
''' 
def factors3(n):
     n = gmpy2.mpz(n)*2 
     B=  gmpy2.isqrt(6*n)
     x = gmpy2.sqrt(twoB**2-
     p = A-x
     q = A+x
     #  sqrt(6*n) close to (3p+2q)/2
'''
#  problem 4

cint = 22096451867410381776306561134883418017410069787892831071731839143676135600120538004282329650473509424343946219751512256465839967942889460764542040581564748988013734864120452325229320176487916666402997509188729971690526083222067771600019329260870009579993724077458967773697817571267229951148662959627934791540
e=65537

#phi = (1-1/p)*(1-1/q)*N
#phi2 = (p-1)*(q-1)

def egcd1(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m
print('')
print('')
print('problem 2')   
factors2(N2)
    
print('')
print('')
print('problem 3')
ans3 = fac3(N3)

print('')
print('')
print('problem 4')
#print('phi:', int(phi))
d = gmpy2.invert(e,phi)
m = gmpy2.powmod(cint,d,N)

hexm = hex(m)
part = hexm.partition('00')
bmess = bytes.fromhex(part[2])
print(bmess.decode())

