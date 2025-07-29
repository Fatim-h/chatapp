import socket
import os
import threading
import hashlib
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from lazyme.string import color_print
import signal

# --- Helper Functions ---

def send_with_length(sock, data: bytes):
    """Send data with a 4-byte length prefix."""
    length = len(data).to_bytes(4, byteorder='big')
    sock.sendall(length + data)

def recv_with_length(sock):
    """Receive data with a 4-byte length prefix."""
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

# --- Global Constants ---
FLAG_READY = "Ready"
FLAG_QUIT = "quit"

# --- Communication Threads ---

def receive_messages():
    """Thread function to receive and decrypt messages from the server."""
    while True:
        try:
            encrypted_msg = recv_with_length(server)
            # Create fresh AES decryptor per message
            decipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)
            decrypted_msg = unpad(decipher.decrypt(encrypted_msg), 16).decode()

            if decrypted_msg == FLAG_QUIT:
                color_print("Server shut down the conversation", color="red", underline=True)
                os.kill(os.getpid(), signal.SIGKILL)
            else:
                color_print(f"\n[!] Server's encrypted message:\n{encrypted_msg}", color="gray")
                print(f"\n[!] SERVER SAID: {decrypted_msg}")
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

def send_messages():
    """Thread function to read user input, encrypt and send messages to the server."""
    while True:
        msg = input("[>] YOUR MESSAGE: ")
        # Create fresh AES encryptor per message
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)
        encrypted = cipher.encrypt(pad(msg.encode(), 16))
        send_with_length(server, encrypted)

        if msg == FLAG_QUIT:
            os.kill(os.getpid(), signal.SIGKILL)
        else:
            color_print(f"\n[!] Your encrypted message:\n{encrypted}", color="gray")

# --- Main Execution ---

if __name__ == "__main__":
    # Generate RSA key pair
    random_func = Random.new().read
    RSAkey = RSA.generate(1024, random_func)
    public_key_bytes = RSAkey.publickey().exportKey()
    private_key_bytes = RSAkey.exportKey()
    rsa_decryptor = PKCS1_OAEP.new(RSAkey)

    # Compute MD5 hash of public key
    my_hash_public = hashlib.md5(public_key_bytes).hexdigest()

    print(public_key_bytes.decode(), "\n\n", private_key_bytes.decode())

    # Get server address and port
    host = input("Host : ")
    port = int(input("Port : "))

    # Save keys to files
    try:
        with open("private.pem", "wb") as f:
            f.write(private_key_bytes)
        with open("public.pem", "wb") as f:
            f.write(public_key_bytes)
    except Exception:
        color_print("Key storing failed", color="red", underline=True)

    # Connect to the server
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect((host, port))
        color_print("Connected to server", color="green", bold=True)
    except Exception:
        color_print("Failed to connect to server", color="red", underline=True)
        exit(1)

    # Send public key and its MD5 hash to server
    payload = public_key_bytes + b":" + my_hash_public.encode()
    send_with_length(server, payload)

    # Receive encrypted session key and server public key (separated by "::")
    response = recv_with_length(server)
    try:
        enc_session, server_pub_bytes = response.split(b"::", 1)
    except ValueError:
        color_print("Invalid server response format", color="red", underline=True)
        exit(1)

    # Import server public key and initialize RSA encryptor
    serverPublic = RSA.import_key(server_pub_bytes)
    rsa_encryptor = PKCS1_OAEP.new(serverPublic)

    color_print("\n[!] Server's public key\n", color="blue")
    print(serverPublic.exportKey().decode())

    # Decrypt session information sent by server
    try:
        decrypted_session = rsa_decryptor.decrypt(enc_session)
        eightByte, session_hash, server_pub_hash = decrypted_session.split(b":")
    except Exception:
        color_print("Failed to decrypt or parse session info", color="red", underline=True)
        exit(1)

    # Verify session hashes
    calc_session_hash = hashlib.md5(eightByte).hexdigest()
    calc_server_pub_hash = hashlib.md5(server_pub_bytes).hexdigest()

    if calc_session_hash != session_hash.decode() or calc_server_pub_hash != server_pub_hash.decode():
        color_print("Public key or session hash mismatch", color="red", underline=True)
        exit(1)

    # Send back the encrypted eightByte session key to server to confirm
    encrypted_eight = rsa_encryptor.encrypt(eightByte)
    send_with_length(server, encrypted_eight)

    # AES key and IV for symmetric encryption
    aes_key = eightByte + eightByte[::-1]
    aes_iv = aes_key  # Using same bytes for IV (note: consider random IV for better security)

    # Wait for server's READY message
    server_msg_encrypted = recv_with_length(server)
    decipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)
    server_msg = unpad(decipher.decrypt(server_msg_encrypted), 16).decode()
    if server_msg != FLAG_READY:
        color_print("Server not ready", color="red", underline=True)
        exit(1)

    color_print("Secure channel established. Server is ready.", color="blue")

    # Send client username
    client_name = input("\n[>] ENTER YOUR NAME: ")
    send_with_length(server, client_name.encode())

    # Start receive and send threads
    threading.Thread(target=receive_messages, daemon=True).start()
    threading.Thread(target=send_messages, daemon=True).start()

    # Keep main thread alive waiting for signals
    signal.pause()
