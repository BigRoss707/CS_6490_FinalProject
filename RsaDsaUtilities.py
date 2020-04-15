from RsaDsaUtilities_BraedenDiaz import *
from RsaDsaUtilities_Syed import *

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

def testDSA():
    p, q, g = generatePrimes()
    privateKey, publicKey = generateKeys(p, q, g)
    message = input("Enter input: ")
    messageBytes = message.encode()
    r, s = signing(p, q, g, privateKey, messageBytes)
    verification(p, q, g, publicKey, r, s, messageBytes)
    
if __name__ == "__main__":
    testRSA()
    testDSA()
