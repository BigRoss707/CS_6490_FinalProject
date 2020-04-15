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

def createFile(fileName, numberCharacters):
	if os.path.exists(fileName):
		os.remove(fileName)

	fileStream = open(fileName, "w")
	for i in range(numberCharacters):
		fileStream.write("A")
	
	fileStream.close()	

#TODO Need to encrypt and integrity protect
def fileTransfer(sock, k):	
	fileName = "TestFile.txt"
	createFile(fileName, 10000) #this should be about 2KB
	
	encryptedFileName = AesUtilities.encryptAndIntegretyProtect(k.serverEncryption, k.serverAuthentication, fileName)
	sendMessage(sock, encryptedFileName)

	fileStream = open(fileName, "r")	
	contents = fileStream.read()
	sendMessage(sock, contents)

#Returns a keys object with keys filled out or throws an exception
def handshake(sock):
	#TODO complete the function
	return AesUtilities.getTestKeys()

def main():
	print("Server Main")

	serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	serverAddress = ("localhost", 34570)
	serverSocket.bind(serverAddress)
	serverSocket.listen(1)

	while True:
		print('Waiting for client.')
		clientSocket, clientAddress = serverSocket.accept()
		
		try:
			#Handshake Phase
			k = handshake(serverSocket)	

			#File Transfer
			fileTransfer(clientSocket, k)
		except:
			print("Connection to client ended unexpectedly.")
		finally:
			clientSocket.close()

	serverSocket.close()

if __name__ == "__main__":
	main()
