import socket
import sys
import os
import AesUtilities
import time
import subprocess
from keys import keys

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

def createFile(fileName, numberCharacters):
        if os.path.exists(fileName):
                os.remove(fileName)

        fileStream = open(fileName, "w")
        for i in range(numberCharacters):
                fileStream.write("A")
        
        fileStream.close()      

def fileTransfer(sock, ServerencryptKey, ServerauthKey):    
        fileName = "TestFile.txt"
        createFile(fileName, 10000) #this should be about 2KB
        
        # encryptedFileName = AesUtilities.encryptAndIntegretyProtect(k.serverEncryption, k.serverAuthentication, fileName)
        encryptedFileName = AesUtilities.encryptAndIntegretyProtect(ServerencryptKey, ServerauthKey, fileName)
        sendMessage(sock, encryptedFileName)
        
        fileStream = open(fileName, "r")        
        fileContents = fileStream.read()
        # encryptedFileContents = AesUtilities.encryptAndIntegretyProtect(k.serverEncryption,k.serverAuthentication, fileContents)
        encryptedFileContents = AesUtilities.encryptAndIntegretyProtect(ServerencryptKey, ServerauthKey, fileContents)

        sendMessage(sock,encryptedFileContents)

#Returns a keys object with keys filled out or throws an exception
def handshake(sock):

        # Receive client hello message
        clientHello = sock.recv(100)

        # Get client's Ra
        Ra = clientHello[5:]

        # Generate and reply with Rb to client
        Rb = AesUtilities.generateNonce()
        sock.sendall(Rb)

        # Compute Master key
        MasterKey = AesUtilities.generateMasterKey(Ra,Rb)

        # Generate Encryption and Authentication keys
        ServerencryptKey, ServerauthKey = AesUtilities.generateSSLKeys(MasterKey,Ra,Rb)

        # return AesUtilities.getTestKeys()
        return ServerencryptKey, ServerauthKey

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
                        startTime = time.perf_counter()
                        
                        #Handshake Phase
                        ## k = handshake(serverSocket)
                        ServerencryptKey, ServerauthKey = handshake(clientSocket)
 
                        afterHandshake = time.perf_counter()
                        
                        #File Transfer
                        fileTransfer(clientSocket, ServerencryptKey, ServerauthKey)

                        afterFileTransfer = time.perf_counter()
                        
                        print('Time elapsed during handshake: ' + str(afterHandshake - startTime))
                        print('Time elapsed during fileTransfer: ' + str(afterFileTransfer - afterHandshake))
                        print('Total time elapsed: ' + str(afterFileTransfer - startTime))
                #except:
                #       print("Connection to client ended unexpectedly.")
                finally:
                        clientSocket.close()

        serverSocket.close()

if __name__ == "__main__":
        main()
