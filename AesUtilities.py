import base64
import hashlib
import hmac
import keys
#import Crypto.Cipher
from Crypto.Cipher import AES
from Crypto import Random

BlockSize = 16

def pad(message):
	#Pad the string with the character(0-15) corresponding to the amount of space remaining in the block
	message = message + (BlockSize - len(message) % BlockSize) * chr(BlockSize - len(message))
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
	return base64.b64encode(iv + cipher.encrypt(message))

def decryptAes256(key, message):
	message = base64.b64decode(message)
	iv = message[:16]
	cipher = AES.new(key, AES.MODE_CBC, iv)
	decryptedMessage = cipher.decrypt(message[16:])
	return unpad(decryptedMessage)

#message should be encoded
def getDigest(key, message):
	h = hmac.new(key, message, hashlib.sha256)
	return h.hexdigest()

def getTestKeys():
	#We use the same password to generate keys so the client/server share keys for the test case	
	testPassword = 'password'
	key1 = hashlib.sha256((testPassword + '1').encode()).digest()
	key1 = hashlib.sha256((testPassword + '2').encode()).digest()	
	key1 = hashlib.sha256((testPassword + '3').encode()).digest()	
	key1 = hashlib.sha256((testPassword + '4').encode()).digest()		
	keyStore = keys(key1, key2, key3, key4)
	return keyStore
	 	
