from socket import *
import thread

# this function is ran within a new thread whenever a new client connects.
def clientHandler(clientConnectionSocket, addr):

    while True:

        clientMessage = clientConnectionSocket.recv(1024).decode()
        clientConnectionSocket.send(clientMessage.encode())

    clientConnectionSocket.close()


serverPort = 12000

serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.bind(('', serverPort))
serverSocket.listen(5)

print('The server is ready to receive')

while True:
    connectionSocket, addr = serverSocket.accept()

    thread.start_new_thread(clientHandler, (connectionSocket, addr))

serverSocket.close()
