# ConfiChat
Chat server project with modern security features. Networking project for CS176B @ UCSB.
## Instructions
Run server.py on server computer.
Run client.py with IP address of server as an argument. e.g. `python client.py 192.168.1.2`

## Description
The server program waits for connections from any number of clients. The server has a record of all established user accounts (secured with hash/salt), and prompts a client to send over their username and password upon connection. The server then helps connect two clients for a chat. All messages sent between client and server are encrypted and authenticated.
The client program uses the server to connect and chat with other clients. All messages between two clients are also encrypted and authenticated.
