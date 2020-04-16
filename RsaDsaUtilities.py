from RsaDsaUtilities_BraedenDiaz import *
from RsaDsaUtilities_Syed import *

"""
    A function that generates two sets of key pairs: one pair of public and
    private keys generated using DSA key generation for signing and verification,
    and another pair of public and private keys generated using RSA key generation
    for encryption and decryption.
"""
def generateRsaDsaKeyPairs():
    p, q, g = generatePrimes()

    # DSA keys used for signing and verification
    privateKeyOne, publicKeyOne = generateKeys(p, q, g)

    # RSA keys used for encryption and decryption
    publicKeyTwo, privateKeyTwo = generateRSAKeyPair(p, q)

    return (privateKeyOne, publicKeyOne, publicKeyTwo, privateKeyTwo, p, q, g)

"""
    A function that encrypted a message using RSA and signs that message using DSA.
"""
def encryptAndSign(publicKeyEncrypt, privateKeySign, p, q, g, messageBytes):
    # Encrypt the provided messageBytes using the publicKey for encryption
    encryptedMessageBytes = encryptWithRSA(publicKeyEncrypt, messageBytes)
    
    # Sign the encrypted messageBytes with the private key for signing
    signatureOfEncryptedMessage = signing(p, q, g, privateKeySign, encryptedMessageBytes)

    # Return the encrypted message bytes along with its signature
    return (encryptedMessageBytes, signatureOfEncryptedMessage)
    

"""
    A function that verifys the signature for an ecnrypted message using DSA and then
    decrypts the message using RSA.
"""
def decryptAndVerify(privateKeyDecrypt, publicKeyVerify, signature, p, q, g, encryptedMessageBytes):
    # Verify the provided signature for the encryptedMessageBytes with the public key for verification
    verified = verification(p, q, g, publicKeyVerify, signature, encryptedMessageBytes)

    # If the signature verification fails, do NOT decrypt and simply raise an Exception.
    # The Exception can be caught and handled by the user of this function.
    if not verified:
        raise Exception("Verification of message failed!")

    # If the verification passed, then decrypt the encryptedMessageBytes with the private key for decryption
    decryptedMessageBytes = decryptWithRSA(privateKeyDecrypt, encryptedMessageBytes)

    # Return the decrypted message bytes
    return decryptedMessageBytes


# A function that tests the RsaDsa combination algorithm
def testRsaDsa():
    message = input("Enter Input: ")
    messageBytes = message.encode()

    print()

    print("Generating RSA and DSA key-pairs, please wait...\n")

    privateKeySign, publicKeyVerify, publicKeyEncrypt, privateKeyDecrypt, p, q, g = generateRsaDsaKeyPairs()

    print("Encrypting and signing...\n")

    encryptedMessageBytes, signature = encryptAndSign(publicKeyEncrypt, privateKeySign, p, q, g, messageBytes)

    print("Encrypted Message (as hex):\n" + str(encryptedMessageBytes.hex()) + "\n")
    print("Encrypted Message Signature:\n", signature)

    print()

    print("Verifying signature and decrypting...\n")
    
    decryptedMessageBytes = decryptAndVerify(privateKeyDecrypt, publicKeyVerify, signature, p, q, g, encryptedMessageBytes)
    decryptedMessage = decryptedMessageBytes.decode("utf-8")
    print("Verification successful!\n")
    print("Decrypted Message: " + decryptedMessage + "\n")
    
if __name__ == "__main__":
    #testRSA() # Moved to it's original file
    #testDSA() # Moved to it's original file

    testRsaDsa()
    


    
