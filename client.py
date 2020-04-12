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
	print('Client Main')
	serverIp = 'localhost'
	
	if len(sys.argv) > 1:
		serverIp = sys.argv[1]

	serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	serverAddress = (serverIp, 34568)
	serverSocket.connect(serverAddress)

	message1 = receiveMessage(serverSocket)
	print(message1)

	sendMessage(serverSocket, 'hello world!')

if __name__ == "__main__":
	main()



