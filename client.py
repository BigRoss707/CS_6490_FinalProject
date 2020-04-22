import socket
import sys
import os
import AesUtilities
import time
from keys import keys
import RsaDsaUtilities
import RsaDsaUtilities_Syed


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
        
        # Generate client's RSA/DSA key pair (Key one is DSA, key Two is RSA)
        privateKeyOne, publicKeyOne, publicKeyTwo, privateKeyTwo, p, q, g = RsaDsaUtilities.generateRsaDsaKeyPairs()

        # Generate Ra
        Ra = AesUtilities.generateNonce()

        # Send Hello, RSA public key, DSA public key
        clientHello = 'Hello'.encode() + RsaDsaUtilities_Syed.int2bytes(publicKeyTwo[0], 'big') + RsaDsaUtilities_Syed.int2bytes(publicKeyTwo[1], 'big') + RsaDsaUtilities_Syed.int2bytes(publicKeyOne, 'big')
        sock.sendall(clientHello)

        # Receive Encrypted Rb, RSA-public, DSA-public [p,q,g] from server
        ReplyFromServer = sock.recv(600)
        encryptedRb = ReplyFromServer[0:104]
        ServerEncryptedSignature = (int.from_bytes(ReplyFromServer[104:124],'big'),int.from_bytes(ReplyFromServer[124:144],'big'))
        ServerRsaPublic = (int.from_bytes(ReplyFromServer[144:145],'big'),int.from_bytes(ReplyFromServer[145:249],'big'))
        ServerDsaPublic = int.from_bytes(ReplyFromServer[249:333],'big')
        Server_p = int.from_bytes(ReplyFromServer[333:417],'big')
        Server_q = int.from_bytes(ReplyFromServer[417:437],'big')
        Server_g = int.from_bytes(ReplyFromServer[437:521],'big')

        # Decrypt Rb and extract server's RSA-public, DSA-public
        Rb = RsaDsaUtilities.decryptAndVerify(privateKeyTwo,ServerDsaPublic,ServerEncryptedSignature, Server_p, Server_q, Server_g, encryptedRb)

        # Compute Master key
        MasterKey = AesUtilities.generateMasterKey(Ra,Rb)

        # Encrypt Ra with server's RSA-public and sign with client's DSA-private
        encryptedMessageBytes, signatureOfEncryptedMessage = RsaDsaUtilities.encryptAndSign(ServerRsaPublic, privateKeyOne, p, q, g, Ra)

        # Send Ra to server
        ClientReply = encryptedMessageBytes + RsaDsaUtilities_Syed.int2bytes(signatureOfEncryptedMessage[0], 'big') + RsaDsaUtilities_Syed.int2bytes(signatureOfEncryptedMessage[1], 'big') + RsaDsaUtilities_Syed.int2bytes(p,'big') + RsaDsaUtilities_Syed.int2bytes(q,'big') + RsaDsaUtilities_Syed.int2bytes(g,'big')
        sock.sendall(ClientReply)
       
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



