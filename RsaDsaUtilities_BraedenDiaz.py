

import sys, os, random, math

"""

Author: Braeden Diaz
 Class: CS6490 Final Project

 Class containing multiple number theory functions to perform the
 math required for RSA/DSA encryption/decryption and sigining/verification.

"""

def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)

def modexp(m, d, n):
    # Initalize the value
    value = 1

    # Convert the exponent d to a binary string
    dBinary = format(d, 'b')

    # For each binary string digit
    for num in dBinary:
        # Square the value, initally set as 1 above
        value = pow(value, 2)

        # If the digit is a "1"
        if num == "1":
            # Mulitply the the current value by the base
            value = value * m

        # Perform a modular reduction after each iteration to keep
        # the intermmediate results small.
        value = value % n

    return value

def inverse(a, N):
    xyd = extendedEuler(a, N)
    g = xyd[0]
    x = xyd[1]

    if g == 1:
        return x % N
    else:
        raise Exception("gcd(a, b) != 1")

def extendedEuler(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        b_div_a, b_mod_a = divmod(b, a)
        g, x, y = extendedEuler(b_mod_a, a)
        return (g, y - b_div_a * x, x)


# Probabalistic Primality Test based on Fermat's Little Theorem
def isPrime(N, numberOfTrials):
    if N == 2:
        return True

    if N < 2 or N % 2 == 0:
        return False

    LOWER_RANGE = 2
    UPPER_RANGE = N

    for i in range(0, numberOfTrials):
        randomNumber = random.randint(LOWER_RANGE, UPPER_RANGE)

        if gcd(randomNumber, N) != 1:
            return False
        else:
            if modexp(randomNumber, N - 1, N) != 1:
                return False

    return True

def randomIntFromBytes(numOfBytes):
    return int.from_bytes(os.urandom(numOfBytes), "big")
    
def generateRSAKeyPair(p=None, q=None):

    if not p:
        p = -1
        while not isPrime(p, 150):
            p = randomIntFromBytes(128)

    if not q:
        q = -1
        while not isPrime(q, 150):
            q = randomIntFromBytes(128)

##    print(p)
##    print(q)

    N = p * q
    phi = (p - 1) * (q - 1)
    e = 0
    d = 0

    for i in range(2, phi):
        if gcd(i, phi) == 1:
            e = i
            break

    d = inverse(e, phi)

    return ((e, N), (d, N))

def encryptWithRSA(publicKey, messageBytes):
    num = int.from_bytes(messageBytes, "big")
    
    e = publicKey[0]
    N = publicKey[1]
    
    if not (num < N):
        raise Exception("[Error] The number " + str(num) + " must be less than the modulus N.")

    return int2bytes(modexp(num, e, N), "big")

def decryptWithRSA(privateKey, encryptedMessageBytes):
    encryptedNum = int.from_bytes(encryptedMessageBytes, "big")

    d = privateKey[0]
    N = privateKey[1]

    if not (encryptedNum < N):
        raise Exception("[Error] The encrypted number " + str(encryptedNum) + " is not less than the modulus N.")

    return int2bytes(modexp(encryptedNum, d, N), "big")

def int2bytes(n, byteorder):
    
    bytes_required = max(1, math.ceil(n.bit_length() / 8))

    return n.to_bytes(bytes_required, byteorder)

# A function used for testing RSA encryption and decryption
def testRSA():
    message = input("Enter Input: ")
    messageBytes = message.encode()

    print()

    print("Generating key-pair, please wait...\n")

    publicKey, privateKey = generateRSAKeyPair()

    print("Encrypting...\n")

    encryptedMessageBytes = encryptWithRSA(publicKey, messageBytes)
    print("Encrypted Message (as bytes):\n" + str(encryptedMessageBytes)  + "\n")
    print("Encrypted Message (as hex):\n" + str(encryptedMessageBytes.hex()) + "\n")

    decryptedMessageBytes = decryptWithRSA(privateKey, encryptedMessageBytes)
    decryptedMessage = decryptedMessageBytes.decode("utf-8")
    print("Decrypted Message: " + decryptedMessage + "\n")
    
if __name__ == "__main__":
    testRSA()

    
    
