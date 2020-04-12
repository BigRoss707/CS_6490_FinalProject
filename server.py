import socket
import sys
import keys

def sendMessage(sock, message):
	#Send the message over the socket
	messageLength = len(message)	
	socketMessage = str(messageLength) + ',' + message
	sock.sendall(socketMessage)

def receiveMessage(sock):
	message = sock.recv(1024)
	splitMessage = message.split(',')
	while len(splitMessage[1]) < int(splitMessage[0]):
		splitMessage[1] += sock.recv()
	return splitMessage[1]

def main():
	print('Server Main')

	serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	serverAddress = ('localhost', 34568)
	serverSocket.bind(serverAddress)
	serverSocket.listen(1)

	while True:
		print('Waiting for client.')
		clientSocket, clientAddress = serverSocket.accept()
		
		try:
			sendMessage(clientSocket, 'hello world!')
			message1 = receiveMessage(clientSocket)
			print(message1)
		except:
			print("Connection to client ended unexpectedly.")
		finally:
			clientSocket.close()

	serverSocket.close()

if __name__ == "__main__":
	main()
