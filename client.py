from socket import *
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Util import Counter
from sys import exit
import signal, os, sys
import pickle
import thread
import ast

def signal_handler(signum, frame):
    print "Closing connection"
    clientSocket.send("11")
    clientSocket.close()
    exit()

def receiveHandler(clientSocket, clientDecryptAES):
    global messagesEnabled
    while True:
        serverMessage = clientSocket.recv(1024)
        if serverMessage[0:2] == "10":
            plaintext = clientDecryptAES.decrypt(serverMessage[2:])
            print '\rFrom ' + buddyName + ':', plaintext
            sys.stdout.write('Enter message: ')
            sys.stdout.flush()
        elif serverMessage[0:2] == "12":
            messagesEnabled = True
            print(chr(27) + "[2J")
            print "Chat with " + buddyName
        elif serverMessage[0:2] == "13":
            print "Connection closed. Other user disconnected."
            clientSocket.send("11")
            clientSocket.close()
            exit()

serverName = 'localhost'
serverPort = 12000

clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((serverName, serverPort))

signal.signal(signal.SIGINT, signal_handler)
new = True
requestedConnect = False
messagesEnabled = False

keygenRandom = Random.new().read
rsaKey = RSA.generate(1024, keygenRandom)
publicKey = rsaKey.publickey()

serverKey = Random.new().read(16)
serverIv = Random.new().read(16)
serverEncryptCtr = Counter.new(128, initial_value=long(serverIv.encode("hex"), 16))
serverEncryptAES = AES.new(serverKey, AES.MODE_CTR, counter=serverEncryptCtr)
serverDecryptCTR = Counter.new(128, initial_value=long(serverIv.encode("hex"), 16))
serverDecryptAES = AES.new(serverKey, AES.MODE_CTR, counter=serverDecryptCTR)

while (1): #setup
    setupMessage = clientSocket.recv(1024)

    if setupMessage[0:2] == "00":
        username = raw_input('Enter Username: ')
        password = raw_input('Enter Password: ')
        clientSocket.send(serverEncryptAES.encrypt(username + "#" + password))

    elif setupMessage[0:2] == "01":
        print(chr(27) + "[2J")
        if (new):
            print("Welcome " + username + "!")
            new = False
        elif (buddyName != ""):
            print "User " + buddyName + " is not avaiable or does not exist."
        print("Users connected:")
        connected = 0
        for x in pickle.loads(serverDecryptAES.decrypt(setupMessage[2:])):
            if (len(x.split("#")) > 1 and x.split("#")[1] == username):
                clientSocket.send("06" + serverEncryptAES.encrypt(x))
                buddyName = x.split("#")[0]
                requestedConnect = True
                break
            elif (x != username):
                connected = connected + 1
                print(x)
        if not requestedConnect:
            if connected == 0:
                print("Nobody else connected currently")
            buddyName = raw_input('Select user to talk to (or press enter to refresh): ')
            clientSocket.send("03" + serverEncryptAES.encrypt(buddyName))

    elif setupMessage[0:2] == "02":
        print("Incorrect Username/Password or already logged in")
        clientSocket.close()
        exit()

    elif setupMessage[0:2] == "04":
        print(chr(27) + "[2J")
        clientSocket.send("09" + publicKey.exportKey('PEM')) # send public key
        print "Waiting for " + buddyName + "...\n"
        keyAndIV = clientSocket.recv(1024).split("##") # then receive the encrypted key and iv
        clientKey = rsaKey.decrypt(ast.literal_eval(str(keyAndIV[0]))) # get the key
        clientIv = rsaKey.decrypt(ast.literal_eval(str(keyAndIV[1]))) # get the IV
        clientEncryptCtr = Counter.new(128, initial_value=long(clientIv.encode("hex"), 16))
        clientEncryptAES = AES.new(clientKey, AES.MODE_CTR, counter=clientEncryptCtr)
        clientDecryptCTR = Counter.new(128, initial_value=long(clientIv.encode("hex"), 16))
        clientDecryptAES = AES.new(clientKey, AES.MODE_CTR, counter=clientDecryptCTR)
        break

    elif setupMessage[0:2] == "07":
        buddyPublicKey = setupMessage[2:]
        buddyPublicKey = RSA.importKey(buddyPublicKey)
        clientKey = Random.new().read(16)
        clientIv = Random.new().read(16)
        clientEncryptCtr = Counter.new(128, initial_value=long(clientIv.encode("hex"), 16))
        clientEncryptAES = AES.new(clientKey, AES.MODE_CTR, counter=clientEncryptCtr)
        clientDecryptCTR = Counter.new(128, initial_value=long(clientIv.encode("hex"), 16))
        clientDecryptAES = AES.new(clientKey, AES.MODE_CTR, counter=clientDecryptCTR)
        keyAndIV = str(buddyPublicKey.encrypt(clientKey, 32)) + "##" + str(buddyPublicKey.encrypt(clientIv, 32))
        clientSocket.send(keyAndIV)
        print(chr(27) + "[2J")
        print "Chat requested from " + buddyName + "\n"
        messagesEnabled = True
        clientSocket.send("12")
        break

    elif setupMessage[0:2] == "08":
        # receive the public key from the server and send the key and IV encrypted with this so only the server can decrypt
        serverPublicKey = setupMessage[2:]
        serverPublicKey = RSA.importKey(serverPublicKey)
        keyAndIV = str(serverPublicKey.encrypt(serverKey, 32)) + "##" + str(serverPublicKey.encrypt(serverIv, 32))
        clientSocket.send(keyAndIV)

    else:
        print "Error: Failed setup"
        clientSocket.close()
        exit()

thread.start_new_thread(receiveHandler, (clientSocket, clientDecryptAES))
while True:
    if messagesEnabled:
        try:
            sentence = raw_input("Enter message: ")
        except:
            exit()

        ciphertext = clientEncryptAES.encrypt(sentence)
        try:
            clientSocket.send("10" + ciphertext)
        except:
            break

clientSocket.close()
