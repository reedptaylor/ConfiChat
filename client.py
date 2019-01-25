from socket import *
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter

serverName = 'localhost'
serverPort = 12000

clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((serverName, serverPort))

key = Random.new().read(16)
iv = Random.new().read(16)
encryptCtr = Counter.new(128, initial_value=long(iv.encode("hex"), 16))
encryptAES = AES.new(key, AES.MODE_CTR, counter=encryptCtr)
decryptCTR = Counter.new(128, initial_value=long(iv.encode("hex"), 16))
decryptAES = AES.new(key, AES.MODE_CTR, counter=decryptCTR)


while True:
    sentence = raw_input('Enter message: ')

    ciphertext = encryptAES.encrypt(sentence)
    clientSocket.send(ciphertext)

    serverMessage = clientSocket.recv(1024)
    plaintext = decryptAES.decrypt(serverMessage)
    print 'From Server: ', plaintext

clientSocket.close()
