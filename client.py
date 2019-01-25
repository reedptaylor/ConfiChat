from socket import *

serverName = 'localhost'
serverPort = 12000

clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((serverName, serverPort))

while True:
    sentence = raw_input('Enter message: ')
    clientSocket.send(sentence.encode())

    serverMessage = clientSocket.recv(1024)
    print 'From Server: ', serverMessage.decode()

clientSocket.close()
