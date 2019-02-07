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
    serverMessage = clientSocket.recv(1024)
    if serverMessage[0:2] == "10":
        plaintext = clientDecryptAES.decrypt(serverMessage[2:])
        print '\nFrom ' + buddyName + ':', plaintext
        sys.stdout.write('Enter message: ')
        sys.stdout.flush()

serverName = 'localhost'
serverPort = 12002

clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((serverName, serverPort))

signal.signal(signal.SIGINT, signal_handler)

keygenRandom = Random.new().read
rsaKey = RSA.generate(1024, keygenRandom)
publicKey = rsaKey.publickey()
# encrypted = publicKey.encrypt('encrypt this message', 32)
# print 'encrypted message:', encrypted
# decrypted = rsaKey.decrypt(ast.literal_eval(str(encrypted)))
# print 'decrypted', decrypted


# clientKey = Random.new().read(16)
clientKey = 'aaaaaaaaaaaaaaaa'
# clientIv = Random.new().read(16)
clientIv = 'aaaaaaaaaaaaaaaa'
clientEncryptCtr = Counter.new(128, initial_value=long(clientIv.encode("hex"), 16))
clientEncryptAES = AES.new(clientKey, AES.MODE_CTR, counter=clientEncryptCtr)
clientDecryptCTR = Counter.new(128, initial_value=long(clientIv.encode("hex"), 16))
clientDecryptAES = AES.new(clientKey, AES.MODE_CTR, counter=clientDecryptCTR)

# serverKey = Random.new().read(16)
serverKey = 'bbbbbbbbbbbbbbbb'
# serverIv = Random.new().read(16)
serverIv = 'bbbbbbbbbbbbbbbb'
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
        print("Welcome " + username + "!")
        print("Users connected:")
        for x in pickle.loads(serverDecryptAES.decrypt(setupMessage[2:])):
            print(x)
        buddyName = raw_input('Select user to talk to: ')
        clientSocket.send("03" + serverEncryptAES.encrypt(buddyName))

    elif setupMessage[0:2] == "02":
        print("Incorrect Username/Password or already logged in")
        clientSocket.close()
        exit()

    elif setupMessage[0:2] == "04":
        break #TEMP

    else:
        print "Error: Failed setup"
        clientSocket.close()
        exit()

while True:

    thread.start_new_thread(receiveHandler, (clientSocket, clientDecryptAES))

    sentence = raw_input('Enter message: ')

    ciphertext = clientEncryptAES.encrypt(sentence)
    clientSocket.send("10" + ciphertext)

clientSocket.close()
