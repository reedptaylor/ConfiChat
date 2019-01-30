###
#Alerts: 00=enter user/pass, 01 successful login, 02, failed log in, 11 close connection, 03 select user, 04 successful select, 05 failed select
#Message Format: "10message" where message is the text to send
###
from socket import *
from Crypto.Cipher import AES
from Crypto import Random
import thread
import pickle

activeUsers = []

#check user name and password for logging in
def checkuser(username, password):
    global activeUsers
    f = open("users.txt", "r")
    for x in f:
        user = x.split("#") #separate username from password
        if (user[0] == username and user[1].strip("\n") == password and user[0] not in activeUsers):
            activeUsers.append(username)
            return(True)
    return(False)

# this function is run within a new thread whenever a new client connects.
def clientHandler(clientConnectionSocket, addr):
    global activeUsers
    clientConnectionSocket.send("00") #alert client to enter username and password
    username = clientConnectionSocket.recv(1024)
    password = clientConnectionSocket.recv(1024)

    if (checkuser(username, password) == False):
        clientConnectionSocket.send("02") #alert failed log in
        clientConnectionSocket.close()
        return
    else:
        clientConnectionSocket.send("01" + pickle.dumps(activeUsers))

    while True:
        clientMessage = clientConnectionSocket.recv(1024)

        if clientMessage[0:2] == "03": #select user
            friend = clientMessage[2:]
            match = friend in activeUsers #find active user not complete
            if (match):
                clientConnectionSocket.send("04")
            else:
                clientConnectionSocket.send("01" + pickle.dumps(activeUsers))

        if clientMessage[0:2] == "11": #code to close
            break

        if clientMessage[0:2] == "10":
            clientConnectionSocket.send(clientMessage)

    clientConnectionSocket.close()
    activeUsers.remove(username)
    return

serverPort = 12000

serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.bind(('', serverPort))
serverSocket.listen(5)

print('The server is ready to receive')

while True:
    connectionSocket, addr = serverSocket.accept()
    print("client connected @", addr, " ", connectionSocket)

    thread.start_new_thread(clientHandler, (connectionSocket, addr))

serverSocket.close()
