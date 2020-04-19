import base64
import hashlib
import hmac
from keys import keys
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import MD5, SHA1

import time, struct

BlockSize = 16

# ****** Key Functions Added by Braeden ****** #

# Returns 32 bytes (256-bits) of randomness with the first four bytes being the Unix time (epoch, since 1970)
def generateNonce():
        # Pack the time into a double (8-bytes) but only use the first 4-bytes as
        # those are the ones that are changing with time.
        return struct.pack("d", time.time())[0:4] + Random.get_random_bytes(28)

# Takes two byte strings and xors each bit together
def xorBytes(bytesA, bytesB):
        return bytes([a ^ b for a, b in zip(bytesA, bytesB)])

# Generates a master key by xoring the two provided nonces together
def generateMasterKey(Ra, Rb):
        return xorBytes(Ra, Rb)

"""
    Implementation of SSLv3 PRF function as described in RFC-6101:
    https://tools.ietf.org/html/rfc6101#page-37
    
     SSLv3-PRF(secret, seed) =
        MD5(secret || SHA-1("A" || secret || seed)) ||
        MD5(secret || SHA-1("BB" || secret || seed)) ||
        MD5(secret || SHA-1("CCC" || secret || seed)) || ...
        
    The requestedLength should not be more than  26 x hashLength (16 in this case) = 416.
"""
def SSLv3PRF(masterKey, RaSeed, RbSeed, requestedLength):
    alphaBytes = [b"A", b"B", b"C", b"D", b"E", b"F", b"G", b"H", b"I", b"J", b"K", b"L",
         b"M", b"N", b"O", b"P", b"Q", b"R", b"S", b"T", b"U", b"V", b"W", b"X",
         b"Y", b"Z"]

    finalResult = b""
    
    hashLength = 16

    rounds = requestedLength + (hashLength - 1)

    for i in range(rounds):
        letters = alphaBytes[i % 26] * (i + 1)
        sha1Digest = SHA1.new(letters + masterKey + RaSeed + RbSeed).digest()
        finalResult += MD5.new(masterKey + sha1Digest).digest()

    return finalResult[:requestedLength]

def generateSSLKeys(masterKey, Ra, Rb):
        # Represents a 64-byte sized block from which the keys will come from
        keyBlock = SSLv3PRF(masterKey, Ra, Rb, 64)

        # Chop up the block into a 32-byte (256-bit) encryption key and authentication key
        encryptKey = keyBlock[0:32]
        authKey = keyBlock[32:64]

        return (encryptKey, authKey)

# ****** End of Key Functions ****** #

# ****** AES Functions Added by Jacob ****** #

def pad(message):
	#Pad the string with the character(0-15) corresponding to the amount of space remaining in the block
	message = message + (BlockSize - len(message) % BlockSize) * chr(BlockSize - len(message) % BlockSize)
	return message

def unpad(message):
	#get the last character of the padding
	lastCharacter = message[len(message) - 1:]

	#read until you hit the first padding character
	#python arrays read backwards with negative numbers
	#so -ord yields the last character inclusive of the message
	return message[:-ord(lastCharacter)]

def encryptAndIntegretyProtect(encryptionKey, authenticationKey, message):
	digest = getDigest(authenticationKey, message.encode())
	encryptedMessage = encryptAes256(encryptionKey, digest + ',' + message)
	return encryptedMessage

def decryptAndIntegretyProtect(encryptionKey, authenticationKey, message):
	decryptedMessage = decryptAes256(encryptionKey, message)
	splitDecryptedMessage = decryptedMessage.split(',')
	digest = getDigest(authenticationKey, splitDecryptedMessage[1].encode())
	if digest != splitDecryptedMessage[0]:
		#raise an error if the message integrety was broken		
		raise ValueError('Keyed message digest of message did not match that sent in the message')
	else:
		return splitDecryptedMessage[1]

def encryptAes256(key, message):
	message = pad(message)
	iv = Random.new().read(AES.block_size)
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return base64.b64encode(iv + cipher.encrypt(message.encode())).decode()

def decryptAes256(key, message):
	message = base64.b64decode(message.encode())
	iv = message[:16]
	cipher = AES.new(key, AES.MODE_CBC, iv)
	decryptedMessage = cipher.decrypt(message[16:])
	return unpad(decryptedMessage).decode()

#message should be encoded
def getDigest(key, message):
	h = hmac.new(key, message, hashlib.sha256)
	return h.hexdigest()

def getTestKeys():
	#We use the same password to generate keys so the client/server share keys for the test case	
	testPassword = 'password'
	key1 = hashlib.sha256((testPassword + '1').encode()).digest()
	key2 = hashlib.sha256((testPassword + '2').encode()).digest()	
	key3 = hashlib.sha256((testPassword + '3').encode()).digest()	
	key4 = hashlib.sha256((testPassword + '4').encode()).digest()		
	keyStore = keys(key1, key2, key3, key4)
	return keyStore

if __name__ == "__main__":
        # Generate two nonces Ra representing Alice and Rb representing Bob
        Ra = generateNonce()
        # Represents time between creating nonces
        time.sleep(1)
        Rb = generateNonce()

        print("Nonce Ra: ", Ra.hex())
        print("Length: " + str(int(len(Ra.hex()) / 2)) + " bytes\n")
        
        print("Nonce Rb: ", Ra.hex())
        print("Length: " + str(int(len(Rb.hex()) / 2)) + " bytes\n")

        # Generate the master key from two nonces
        masterKey = generateMasterKey(Ra, Rb)

        print("Master Key: ", masterKey.hex())
        print("Length: " + str(int(len(masterKey.hex()) / 2)) + " bytes\n")

        # Generate the encryption and authentication key from the master key and nonces
        # Note: You will call this once from the client and once from the server.
        encryptKey, authKey = generateSSLKeys(masterKey, Ra, Rb)

        print("Encryption Key: ", encryptKey.hex())
        print("Length: " + str(int(len(encryptKey.hex()) / 2)) + " bytes\n")
        print("Authentication Key: ", authKey.hex())
        print("Length: " + str(int(len(authKey.hex()) / 2)) + " bytes\n")
        
        

