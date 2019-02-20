###
#Alerts: 00=enter user/pass, 01 successful login, 02, failed log in, 11 close connection, 03 select user, 04 successful select, 05 failed select, 06 accepting request, 07 successful link, 08 server encryption setup, 09 client encryption setup, 12 other user connected, 13 end connection, 20 for creating new account
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
import hmac
import hashlib
import base64

# globally defined variables which are thread safe and used between client threads
activeUsers = []
activeSockets = []
clientPublicKeys = {}

#check user name and password for logging in
def checkuser(username, password, clientConnectionSocket):
    global activeUsers, activeSockets
    f = open("users.txt", "r")
    for x in f:
        user = x.split("#") #separate username from password
        if (user[0] == username and user[1].strip("\n") == password and user[0] not in activeUsers):
            activeUsers.append(username)
            activeSockets.append(clientConnectionSocket)
            f.close()
            return(True)
    return(False)

#check if username is already taken before creting new account
def checkcreate(username, password, clientConnectionSocket):
    global activeUsers, activeSockets
    f = open("users.txt", "r")
    for x in f:
        user = x.split("#") #separate username from password
        if (user[0] == username):
            f.close()
            return(False)
    f.close()
    #not taken:
    f = open("users.txt", "a+") # open for writing now
    f.write(username + "#" + password + "\n")
    activeUsers.append(username)
    activeSockets.append(clientConnectionSocket)
    f.close()
    return(True)


# this function is run within a new thread whenever a new client connects.
def clientHandler(clientConnectionSocket, addr):
    global activeUsers, activeSockets, clientPublicKeys

    requestedConnect = False
    buddySocket = ""

    clientConnectionSocket.send("08" + publicKey.exportKey('PEM')) # first send client the server's public key
    keyAndIV = clientConnectionSocket.recv(1024).split("##") # then receive the encrypted key and iv generated by client
    key = rsaKey.decrypt(ast.literal_eval(str(keyAndIV[0]))) # decrypt the key
    iv = rsaKey.decrypt(ast.literal_eval(str(keyAndIV[1]))) # decrypt the IV

    # now generate the AES objects for symmetric crypto
    encryptCtr = Counter.new(128, initial_value=long(iv.encode("hex"), 16))
    encryptAES = AES.new(key, AES.MODE_CTR, counter=encryptCtr)
    decryptCTR = Counter.new(128, initial_value=long(iv.encode("hex"), 16))
    decryptAES = AES.new(key, AES.MODE_CTR, counter=decryptCTR)

    clientConnectionSocket.send("00") #alert client to enter username and password
    ciphertextAndTag = clientConnectionSocket.recv(1024).split("##") # separate the received ciphertext and tag into a list
    try:
        if(hmac.new(key, ciphertextAndTag[0][2:], hashlib.sha256).hexdigest() != ciphertextAndTag[1]): # make sure the tag matches
            print 'Someone is attempting to manipulate your messages. Exiting now.'
            exit()
    except:
        print ("Client disconnected: ", clientConnectionSocket)
        exit()
    login = decryptAES.decrypt(ciphertextAndTag[0][2:]).split("#")
    username  = login[0]
    password = login[1]

    print username, password, ciphertextAndTag[0][:2]

    if (ciphertextAndTag[0][:2] == "00"): #user is logging in
        if (checkuser(username, password, clientConnectionSocket) == False):
            clientConnectionSocket.send("02") #alert failed log in
            clientConnectionSocket.close()
            return
        else:
            # send the client the list of active users
            ciphertext = encryptAES.encrypt(pickle.dumps(activeUsers))
            tag = hmac.new(key, ciphertext, hashlib.sha256).hexdigest()
            clientConnectionSocket.send("01" + ciphertext + "##" + tag)

    elif (ciphertextAndTag[0][:2] == "20"): #user is creating account
        if (checkcreate(username, password, clientConnectionSocket) == False):
            clientConnectionSocket.send("02") #alert failed log in
            clientConnectionSocket.close()
            returnt
        else:
            # send the client the list of active users
            ciphertext = encryptAES.encrypt(pickle.dumps(activeUsers))
            tag = hmac.new(key, ciphertext, hashlib.sha256).hexdigest()
            clientConnectionSocket.send("01" + ciphertext + "##" + tag)

    while True:
        clientMessage = clientConnectionSocket.recv(1024)

        if clientMessage[0:2] == "03": #select user
            for x in activeUsers:
                if (len(x.split("#")) > 1 and x.split("#")[1] == username):
                    requestedConnect = True
                    break
            ciphertextAndTag = clientMessage[2:].split("##")
            if(hmac.new(key, ciphertextAndTag[0], hashlib.sha256).hexdigest() != ciphertextAndTag[1]):
                print 'Someone is attempting to manipulate your messages. Exiting now.'
                exit()
            friend = decryptAES.decrypt(ciphertextAndTag[0])
            match = friend in activeUsers
            if (match and not requestedConnect):
                buddySocket = activeSockets[activeUsers.index(friend)]
                clientConnectionSocket.send("04")
                activeUsers.remove(friend)
                activeSockets.remove(buddySocket)
                activeUsers[activeUsers.index(username)] = username + "#" + friend #link users together
            else:
                ciphertext = encryptAES.encrypt(pickle.dumps(activeUsers))
                tag = hmac.new(key, ciphertext, hashlib.sha256).hexdigest()
                clientConnectionSocket.send("01" + ciphertext + "##" + tag)

        elif clientMessage[0:2] == "06": #tie connection together
            ciphertextAndTag = clientMessage[2:].split("##")
            if(hmac.new(key, ciphertextAndTag[0], hashlib.sha256).hexdigest() != ciphertextAndTag[1]):
                print 'Someone is attempting to manipulate your messages. Exiting now.'
                exit()
            message = decryptAES.decrypt(ciphertextAndTag[0])
            friend = message.split("#")[0]
            buddySocket = activeSockets[activeUsers.index(message)]
            clientConnectionSocket.send("07" + clientPublicKeys[friend])
            forwardCryptoInit = clientConnectionSocket.recv(1024)
            buddySocket.send(forwardCryptoInit)
            activeUsers.remove(message)
            activeSockets.remove(buddySocket)

        elif clientMessage[0:2] == "09": # get public key to forward to buddy client
            clientPublicKey = clientMessage[2:]
            clientPublicKeys[username] = clientPublicKey

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
