import socket
import sys
import keys
import os
import AesUtilities

def sendMessage(sock, message):
	#Send the message over the socket
	messageLength = len(message)	
	socketMessage = str(messageLength) + ',' + message
	sock.sendall(socketMessage.encode())

def receiveMessage(sock):
	message = sock.recv(1024)
	#print("message: " + message.decode())
	splitMessage = message.decode().split(",")
	while len(splitMessage[1]) < int(splitMessage[0]):
		splitMessage[1] += sock.recv(1024)
	return splitMessage[1]

#TODO Need to encrypt and integrity protect
def fileTransfer(sock):
	testKeys = AesUtilities.getTestKeys()
	
	encryptedFileName = receiveMessage(sock)
	fileName = AesUtilities.decryptAndIntegretyProtect(testKeys.serverEncryption, testKeys.serverAuthentication, fileName)
	print('decrypted file name: ' + fileName)

	fileContents = receiveMessage(sock)
	fileName = "Client_" + fileName #Do this so that the client creates a separate version of the file than the server

	if os.path.exists(fileName):
		os.remove(fileName)

	fileStream = open(fileName, "w")
	fileStream.write(fileContents)

def main():
	print("Client Main")
	serverIp = 'localhost'
	
	if len(sys.argv) > 1:
		serverIp = sys.argv[1]

	serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	serverAddress = (serverIp, 34570)
	serverSocket.connect(serverAddress)

	#Hello World Client
	#message1 = receiveMessage(serverSocket)
	#print(message1)
	#sendMessage(serverSocket, 'hello world!')
	
	#File Transfer
	fileTransfer(serverSocket)

if __name__ == "__main__":
	main()



