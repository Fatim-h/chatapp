# chatapp
A Python-based client-server real-time chat application featuring end-to-end encrypted messaging using RSA and AES cryptography and socket.

- Sockets
- RSA AES encryption for connection
- Messages are padded and encrypted with AES-CBC mod
- Multi-client support with threaded connections
- Clean terminal output with message coloring(lazyme)

One server, many clients. Server broadcasts client message to all clients with username.

## Requirements
- Python 3.7+
- PyCryptodome (pip install pycryptodome)
- lazyme (pip install lazyme)

## Usage
1. Start Server:
   ```bash
   python server.py
   
2. Choose IP and port manually or auto-detect
3. Start Client(on a seperate terminal):
    ```bash
   python client.py
4. After secure handshake, enter your username
5. You can do this for as many clients as you want
6. To end connect, client should enter "quit"

Encryption keys are saved as public.pem and private.pem.

## Test Run(Using VM and venv):
<img width="1569" height="832" alt="image" src="https://github.com/user-attachments/assets/6c243aac-40d3-49a8-bedf-3bea3992749e" />

