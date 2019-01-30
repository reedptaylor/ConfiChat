from socket import *
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter
from sys import exit
import signal, os
import pickle

def signal_handler(signum, frame):
    print "Closing connection"
    clientSocket.send("11")
    clientSocket.close()
    exit()

serverName = 'localhost'
serverPort = 12000

clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((serverName, serverPort))

signal.signal(signal.SIGINT, signal_handler)

key = Random.new().read(16)
iv = Random.new().read(16)
encryptCtr = Counter.new(128, initial_value=long(iv.encode("hex"), 16))
encryptAES = AES.new(key, AES.MODE_CTR, counter=encryptCtr)
decryptCTR = Counter.new(128, initial_value=long(iv.encode("hex"), 16))
decryptAES = AES.new(key, AES.MODE_CTR, counter=decryptCTR)

while (1): #setup
    setupMessage = clientSocket.recv(1024)

    if setupMessage[0:2] == "00":
        username = raw_input('Enter Username: ')
        password = raw_input('Enter Password: ')
        clientSocket.send(username)
        clientSocket.send(password)

    elif setupMessage[0:2] == "01":
        print("Welcome " + username + "!")
        print("Users connected:")
        for x in pickle.loads(setupMessage[2:]):
            print(x)
        clientSocket.send("03" + raw_input('Select user to talk to: '))

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
    sentence = raw_input('Enter message: ')

    ciphertext = encryptAES.encrypt(sentence)
    clientSocket.send("10" + ciphertext)

    serverMessage = clientSocket.recv(1024)
    plaintext = decryptAES.decrypt(serverMessage[2:])
    print 'From Server: ', plaintext

clientSocket.close()
