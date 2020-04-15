from random import *
import random
from hashlib import sha1


def rabinMiller(num,numberOfTrials):
    s = num - 1
    count = 0
    while s % 2 == 0:
        s = s//2
        count += 1

    for trials in range(numberOfTrials):
        a = random.randrange(2,num-1)
        v = pow(a, s, num)
        if v != 1:
            i = 0
            while v != (num-1):
                if i == (count-1):
                    return False
                else:
                    i = i + 1
                    v = (v**2)%num
    return True

def isPrime(num):
    if (num<2) or (num%2 == 0):
        return False
    else:
        return rabinMiller(num,150)


def generatePrimes():
    N = 160 # Number of bits for q
    L = 512 # Number of bits for p

    q = getrandbits(N) # Generate random number with N-bits
    while not(isPrime(q)): # Check of the number is prime
        q = getrandbits(N)
    
    i = 2**L
    p = 0
    while not(isPrime(p)): # q should be a factor of (p-1)
        i += 1 # (p-1)/q
        p = q*i + 1

    g = pow(2, i, p)
    return p, q, g

def generateKeys(p, q, g):
    privateKey = randint(0,q)
    publicKey = pow(g, privateKey, p)
    return privateKey, publicKey

def invert(n,p):
    toitent = p-1
    inverse = pow(n,toitent-1, p)
    return inverse

def hash(m):
    m = bin(m)
    m = sha1(m).hexdigest()
    m = int(m,16)
    return m

def signing(p, q, g, privateKey, message):
    k = randint(0, q)
    r = pow(g, k, p)%q
    s = (invert(k,q)* (hash(message) + privateKey*r))%q
    return (r, s)

def verification(p, q, g, publicKey, r, s, message):
    w = invert(s,q)
    u1 = hash(message)*w % q
    u2 = r*w % q
    v = (pow(g, u1, p)*pow(publicKey, u2, p)%p)%q
    if (v == r):
        print('Message signature matched')
    else:
        print('Message signature did not match')

if __name__ == "__main__":
    p, q, g = generatePrimes()
    privateKey, publicKey = generateKeys(p, q, g)
    message = int(input("Enter a nuber: "))
    r, s = signing(p, q, g, privateKey, message)
    verification(p, q, g, publicKey, r, s, message)



