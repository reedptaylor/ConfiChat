from socket import *
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Util import Counter
from sys import exit, argv
import signal, os, sys
import pickle
import thread
import ast
import hmac
import hashlib
import base64

# catch CTRL-C singal to let the server know the client is disconnecting
def signal_handler(signum, frame):
    print "Closing connection"
    clientSocket.send("11")
    clientSocket.close()
    exit()

# ran in thread for receiving messages from another client
def receiveHandler(clientSocket, clientDecryptAES):
    global messagesEnabled
    while True:
        serverMessage = clientSocket.recv(1024)
        if serverMessage[0:2] == "10":
            ciphertextAndTag = serverMessage[2:].split("##")
            if(hmac.new(clientKey, ciphertextAndTag[0], hashlib.sha256).hexdigest() != ciphertextAndTag[1]):
                print 'Someone is attempting to manipulate your messages. Exiting now.'
                print "Closing connection"
                clientSocket.send("11")
                clientSocket.close()
                exit()
            plaintext = clientDecryptAES.decrypt(ciphertextAndTag[0])
            print '\rFrom ' + buddyName + ':', plaintext
            sys.stdout.write('Enter message: ')
            sys.stdout.flush()
        elif serverMessage[0:2] == "12":
            messagesEnabled = True #other user connected
            print(chr(27) + "[2J") #clear screen
            print "Chat with " + buddyName
        elif serverMessage[0:2] == "13": #disconnect
            print "Connection closed. Other user disconnected."
            clientSocket.send("11")
            clientSocket.close()
            exit()

if len(argv) != 2:
    print "Please provide server IP as CLI argument e.g. python client.py 192.168.1.2"
    exit()

serverName = argv[1]
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
        nextaction = raw_input('Enter \'l\' to login or \'c\' to create account: ')
        while (not (nextaction == "l" or nextaction == "c")):
            print(nextaction + " is not a valid input.")
            nextaction = raw_input('Enter \'l\' to login or \'c\' to create account: ')
        if (nextaction == 'l'): #login
            username = raw_input('Enter Username: ')
            password = raw_input('Enter Password: ')
            ciphertext = serverEncryptAES.encrypt(username + "#" + password)
            tag = hmac.new(serverKey, ciphertext, hashlib.sha256).hexdigest()
            clientSocket.send("00" + ciphertext + "##" + tag)
        elif (nextaction == 'c'): #create new account
            username = raw_input('Enter New Username: ')
            password = raw_input('Enter New Password: ')
            ciphertext = serverEncryptAES.encrypt(username + "#" + password)
            tag = hmac.new(serverKey, ciphertext, hashlib.sha256).hexdigest()
            clientSocket.send("20" + ciphertext + "##" + tag)

    elif setupMessage[0:2] == "01":
        print(chr(27) + "[2J") # clear screen
        if (new):
            if (nextaction == 'c'):
                print("New account successfully created!")
            print("Welcome " + username + "!")
            new = False
        elif (buddyName != ""):
            print "User " + buddyName + " is not avaiable or does not exist."
        print("Users connected:")
        connected = 0
        ciphertextAndTag = setupMessage[2:].split("##")
        if(hmac.new(serverKey, ciphertextAndTag[0], hashlib.sha256).hexdigest() != ciphertextAndTag[1]):
            print 'Someone is attempting to manipulate your messages. Exiting now.'
            print "Closing connection"
            clientSocket.send("11")
            clientSocket.close()
            exit()
        for x in pickle.loads(serverDecryptAES.decrypt(ciphertextAndTag[0])):
            if (len(x.split("#")) > 1 and x.split("#")[1] == username): #if there is a requested connection
                ciphertext = serverEncryptAES.encrypt(x)
                tag = hmac.new(serverKey, ciphertext, hashlib.sha256).hexdigest()
                clientSocket.send("06" + ciphertext + "##" + tag)
                buddyName = x.split("#")[0]
                requestedConnect = True
                break
            elif (x != username and len(x.split("#")) == 1):
                connected = connected + 1
                print(x)
        if not requestedConnect:
            if connected == 0:
                print("Nobody else connected currently")
            buddyName = raw_input('Select user to talk to (or press enter to refresh): ')
            ciphertext = serverEncryptAES.encrypt(buddyName)
            tag = hmac.new(serverKey, ciphertext, hashlib.sha256).hexdigest()
            clientSocket.send("03" + ciphertext + "##" + tag)

    elif setupMessage[0:2] == "02":
        if (nextaction == 'l'):
            print("Incorrect Username/Password or already logged in")
        else:
            print("Username already taken")
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
        # receive your buddy's public key and send him your generated key and IV for symmetric encryption
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
        tag = hmac.new(clientKey, ciphertext, hashlib.sha256).hexdigest()
        try:
            clientSocket.send("10" + ciphertext + "##" + tag)
        except:
            break

clientSocket.close()
