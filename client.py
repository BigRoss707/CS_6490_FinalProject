import socket
import sys
import os
import AesUtilities
import time
from keys import keys
import RsaDsaUtilities

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
                splitMessage[1] += sock.recv(1024).decode()
        return splitMessage[1]

def fileTransfer(sock, ServerEncryptKey, ServerAuthKey):      
        encryptedFileName = receiveMessage(sock)
        # fileName = AesUtilities.decryptAndIntegretyProtect(k.serverEncryption, k.serverAuthentication, encryptedFileName)
        fileName = AesUtilities.decryptAndIntegretyProtect(ServerEncryptKey, ServerAuthKey, encryptedFileName)
        print('decrypted file name: ' + fileName)

        encryptedFileContents = receiveMessage(sock)
        # fileContents = AesUtilities.decryptAndIntegretyProtect(k.serverEncryption, k.serverAuthentication, encryptedFileContents)
        fileContents = AesUtilities.decryptAndIntegretyProtect(ServerEncryptKey, ServerAuthKey, encryptedFileContents)
        fileName = "Client_" + fileName #Do this so that the client creates a separate version of the file than the server

        if os.path.exists(fileName):
                os.remove(fileName)

        fileStream = open(fileName, "w")
        fileStream.write(fileContents)

#Returns a keys object with keys filled out or throws an exception
def handshake(sock):
        
        # Generate Ra
        Ra = AesUtilities.generateNonce()

        # Send Hello with Ra to server
        clientHello = 'Hello'.encode() + Ra
        sock.sendall(clientHello)

        # Receive Rb from server
        Rb = sock.recv(100)

        # Compute Master key
        MasterKey = AesUtilities.generateMasterKey(Ra,Rb)

        # Generate Encryption and Authentication keys
        ServerEncryptKey, ServerAuthKey = AesUtilities.generateSSLKeys(MasterKey,Ra,Rb)

        # return the server authentication and ecryption keys used to receive messages from the server
        return ServerEncryptKey, ServerAuthKey

def main():
        print("Client Main")
        serverIp = 'localhost'
        
        if len(sys.argv) > 1:
                serverIp = sys.argv[1]

        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverAddress = (serverIp, 34570)
        serverSocket.connect(serverAddress)

        startTime = time.perf_counter()
        
        #Handshake Phase
        #We only generate and user Server auth/enc keys because the messages are only one way in this example
        ServerEncryptKey, ServerAuthKey = handshake(serverSocket)

        afterHandshake = time.perf_counter()
        
        #File Transfer
        fileTransfer(serverSocket, ServerEncryptKey, ServerAuthKey)

        afterFileTransfer = time.perf_counter()

        print('Time elapsed during handshake: ' + str(afterHandshake - startTime))
        print('Time elapsed during fileTransfer: ' + str(afterFileTransfer - afterHandshake))
        print('Total time elapsed: ' + str(afterFileTransfer - startTime))
        
if __name__ == "__main__":
        main()



