import socket
import os
import signal
import threading
import hashlib
from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from lazyme.string import color_print

# --- Utility functions ---

def get_ip_address():
    """Dynamically determine the local IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def send_with_length(sock, data: bytes):
    """Send length-prefixed data."""
    length = len(data).to_bytes(4, byteorder='big')
    sock.sendall(length + data)

def recv_with_length(sock):
    """Receive length-prefixed data."""
    length_bytes = sock.recv(4)
    if not length_bytes:
        raise ConnectionError("Connection closed while reading length prefix")
    length = int.from_bytes(length_bytes, byteorder='big')

    data = b""
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            raise ConnectionError("Connection closed while reading data")
        data += packet
    return data

# --- Globals ---

CONNECTION_LIST = []  # List of tuples: (client_name, socket, AESKey_bytes)
FLAG_READY = "Ready"
FLAG_QUIT = "quit"
server = None

# --- Connection Handler ---

def connection_handler():
    while True:
        client, address = server.accept()
        color_print(f"\n[!] Client connecting from {address}", color="green", bold=True)

        try:
            # Receive public key and hash from client
            payload = recv_with_length(client)
            tmpClientPublic, clientPublicHash = payload.split(b":")
            tmpHash = hashlib.md5(tmpClientPublic).hexdigest()

            if tmpHash != clientPublicHash.decode():
                color_print("Public key hash mismatch!", color="red", underline=True)
                client.close()
                continue

            color_print("[+] Public key verified", color="blue")
            clientPublic = RSA.import_key(tmpClientPublic)
            rsa_encryptor = PKCS1_OAEP.new(clientPublic)

            # Prepare session info to send to client
            fSend = b":".join([eightByte, session.encode(), my_hash_public.encode()])
            encrypted_session = rsa_encryptor.encrypt(fSend)
            response_payload = encrypted_session + b"::" + public  # "::" separates parts
            send_with_length(client, response_payload)

            # Get confirmation back (encrypted eightByte)
            encrypted_client_response = recv_with_length(client)
            client_response = rsa_decryptor.decrypt(encrypted_client_response)

            if client_response != eightByte:
                color_print("Session mismatch!", color="red")
                client.close()
                continue

            # Generate AES key and IV
            key_128 = eightByte + eightByte[::-1]

            # Send READY message encrypted
            AESKey = AES.new(key_128, AES.MODE_CBC, iv=key_128)
            ready_msg = AESKey.encrypt(pad(FLAG_READY.encode(), 16))
            send_with_length(client, ready_msg)

            # Receive client name
            client_name = recv_with_length(client).decode()
            CONNECTION_LIST.append((client_name, client, key_128))
            color_print(f"{client_name} IS CONNECTED", color="green", underline=True)

            # Start receive thread for this client
            threading.Thread(target=receive_messages, args=(client_name, client, key_128), daemon=True).start()

        except Exception as e:
            color_print(f"Error during client handshake: {e}", color="red")
            client.close()

# --- Message Handlers ---

def receive_messages(client_name, client_sock, aes_key_bytes):
    """Receive messages from a client, decrypt and broadcast them."""
    while True:
        try:
            data = recv_with_length(client_sock)
            if data:
                cipher_decrypt = AES.new(aes_key_bytes, AES.MODE_CBC, iv=aes_key_bytes)
                message = unpad(cipher_decrypt.decrypt(data), 16).decode()

                if message == FLAG_QUIT:
                    color_print(f"{client_name} left the conversation", color="red", underline=True)
                    CONNECTION_LIST[:] = [(n,s,k) for n,s,k in CONNECTION_LIST if s != client_sock]
                    client_sock.close()
                    break

                color_print(f"\n[!] {client_name} SAID : {message}", color="blue")

                # Broadcast to other clients
                broadcast(client_name, client_sock, message)

        except (ConnectionError, OSError):
            color_print(f"Connection lost from {client_name}", color="red")
            CONNECTION_LIST[:] = [(n,s,k) for n,s,k in CONNECTION_LIST if s != client_sock]
            client_sock.close()
            break
        except Exception as e:
            color_print(f"Receive error from {client_name}: {e}", color="red")
            CONNECTION_LIST[:] = [(n,s,k) for n,s,k in CONNECTION_LIST if s != client_sock]
            client_sock.close()
            break

def broadcast(sender_name, sender_sock, message):
    """Encrypt and send message to all clients except the sender."""
    for name, sock, key_128 in CONNECTION_LIST:
        if sock != sender_sock:
            try:
                cipher_encrypt = AES.new(key_128, AES.MODE_CBC, iv=key_128)
                encrypted_msg = cipher_encrypt.encrypt(pad(f"{sender_name}: {message}".encode(), 16))
                send_with_length(sock, encrypted_msg)
            except Exception as e:
                color_print(f"Broadcast to {name} failed: {e}", color="red")

# --- Main Program ---

if __name__ == "__main__":
    host = ""
    port = 0

    # Generate RSA key pair
    random = Random.new().read
    RSAkey = RSA.generate(1024, random)
    public = RSAkey.publickey().exportKey()
    private = RSAkey.exportKey()
    rsa_decryptor = PKCS1_OAEP.new(RSAkey)

    tmpPub = hashlib.md5(public)
    my_hash_public = tmpPub.hexdigest()

    # Generate session key
    eightByte = os.urandom(8)
    session = hashlib.md5(eightByte).hexdigest()

    # Write keys to files (optional)
    try:
        with open('private.pem', 'wb') as f: f.write(private)
        with open('public.pem', 'wb') as f: f.write(public)
    except Exception:
        color_print("Key storing failed", color="red", underline=True)

    # Choose connection mode
    color_print("[1] Auto connect by broadcast IP & PORT\n[2] Manually enter IP & PORT", color="blue", bold=True)
    choice = input("[>] ")
    if choice == "1":
        host = get_ip_address()
        port = 8080
    elif choice == "2":
        host = input("Host : ")
        port = int(input("Port : "))
    else:
        color_print("Invalid choice", color="red")
        exit(1)

    # Setup server socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)

    color_print(f"[!] Server running at {host}:{port}", color="green", bold=True)

    # Start accepting connections
    threading.Thread(target=connection_handler, daemon=True).start()

    # Keep main thread alive
    while True:
        signal.pause()
