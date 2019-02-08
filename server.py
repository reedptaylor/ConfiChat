###
#Alerts: 00=enter user/pass, 01 successful login, 02, failed log in, 11 close connection, 03 select user, 04 successful select, 05 failed select, 06 accepting request, 07 successful link, 12 other user connected, 13 end connection
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

    requestedConnect = False
    buddySocket = ""

    clientConnectionSocket.send("08" + publicKey.exportKey('PEM')) # first send server public key
    keyAndIV = clientConnectionSocket.recv(1024).split("##") # then receive the encrypted key and iv
    key = rsaKey.decrypt(ast.literal_eval(str(keyAndIV[0]))) # get the key
    iv = rsaKey.decrypt(ast.literal_eval(str(keyAndIV[1]))) # get the IV

    # now generate the AES objects for symmetric crypto
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
            for x in activeUsers:
                if (len(x.split("#")) > 1 and x.split("#")[1] == username):
                    requestedConnect = True
                    break
            friend = decryptAES.decrypt(clientMessage[2:])
            match = friend in activeUsers #find active user not complete
            if (match and not requestedConnect):
                buddySocket = activeSockets[activeUsers.index(friend)]
                clientConnectionSocket.send("04")
                activeUsers.remove(friend)
                activeSockets.remove(buddySocket)
                activeUsers[activeUsers.index(username)] = username + "#" + friend #link users together
            else:
                clientConnectionSocket.send("01" + encryptAES.encrypt(pickle.dumps(activeUsers)))

        elif clientMessage[0:2] == "06": #tie connection together
            message = decryptAES.decrypt(clientMessage[2:])
            friend = message.split("#")[0]
            buddySocket = activeSockets[activeUsers.index(message)]
            clientConnectionSocket.send("07")
            activeUsers.remove(message)
            activeSockets.remove(buddySocket)

        elif clientMessage[0:2] == "11": #code to close
            if buddySocket != "":
                try:
                    buddySocket.send("13")
                except:
                    break
            break

        elif clientMessage[0:1] == "1":
            try:
                buddySocket.send(clientMessage)
            except:
                break

    try:
        activeUsers.remove(username)
        activeSockets.remove(clientConnectionSocket)
    except:
        pass
    print("client disconnected", username, clientConnectionSocket)
    clientConnectionSocket.close()
    return

serverPort = 12000

serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
serverSocket.bind(('', serverPort))
serverSocket.listen(5)

keygenRandom = Random.new().read
rsaKey = RSA.generate(1024, keygenRandom)
publicKey = rsaKey.publickey()

print('The server is initialized')

while True:
    connectionSocket, addr = serverSocket.accept()
    print("client connected @", addr, " ", connectionSocket)

    thread.start_new_thread(clientHandler, (connectionSocket, addr))

serverSocket.close()
