###
#Alerts: 00=enter user/pass, 01 successful login, 02, failed log in, 11 close connection, 03 select user, 04 successful select, 05 failed select
#Message Format: "10message" where message is the text to send
###
from socket import *
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter
from Crypto.PublicKey import RSA
import thread
import pickle
import signal, os
import ast

activeUsers = []
activeSockets = []

#check user name and password for logging in
def checkuser(username, password, clientConnectionSocket):
    global activeUsers, activeSockets
    f = open("users.txt", "r")
    for x in f:
        user = x.split("#") #separate username from password
        if (user[0] == username and user[1].strip("\n") == password and user[0] not in activeUsers):
            activeUsers.append(username)
            activeSockets.append(clientConnectionSocket)
            return(True)
    return(False)

# this function is run within a new thread whenever a new client connects.
def clientHandler(clientConnectionSocket, addr):
    global activeUsers, activeSockets

    # key = Random.new().read(16)
    key = 'bbbbbbbbbbbbbbbb'
    # iv = Random.new().read(16)
    iv = 'bbbbbbbbbbbbbbbb'
    encryptCtr = Counter.new(128, initial_value=long(iv.encode("hex"), 16))
    encryptAES = AES.new(key, AES.MODE_CTR, counter=encryptCtr)
    decryptCTR = Counter.new(128, initial_value=long(iv.encode("hex"), 16))
    decryptAES = AES.new(key, AES.MODE_CTR, counter=decryptCTR)

    clientConnectionSocket.send("00") #alert client to enter username and password
    login = decryptAES.decrypt(clientConnectionSocket.recv(1024)).split("#")
    username  = login[0]
    password = login[1]

    if (checkuser(username, password, clientConnectionSocket) == False):
        clientConnectionSocket.send("02") #alert failed log in
        clientConnectionSocket.close()
        return
    else:
        clientConnectionSocket.send("01" + encryptAES.encrypt(pickle.dumps(activeUsers)))

    while True:
        clientMessage = clientConnectionSocket.recv(1024)

        if clientMessage[0:2] == "03": #select user
            friend = decryptAES.decrypt(clientMessage[2:])
            match = friend in activeUsers #find active user not complete
            if (match):
                buddySocket = activeSockets[activeUsers.index(friend)]
                clientConnectionSocket.send("04")
            else:
                clientConnectionSocket.send("01" + encryptAES.encrypt(pickle.dumps(activeUsers)))

        if clientMessage[0:2] == "11": #code to close
            break

        if clientMessage[0:2] == "10":
            buddySocket.send(clientMessage)

    activeUsers.remove(username)
    activeSockets.remove(clientConnectionSocket)
    clientConnectionSocket.close()
    return

serverPort = 12002

serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
serverSocket.bind(('', serverPort))
serverSocket.listen(5)

keygenRandom = Random.new().read
rsaKey = RSA.generate(1024, keygenRandom)
publicKey = rsaKey.publickey()

print('The server is ready to receive')

while True:
    connectionSocket, addr = serverSocket.accept()
    print("client connected @", addr, " ", connectionSocket)

    thread.start_new_thread(clientHandler, (connectionSocket, addr))

serverSocket.close()
