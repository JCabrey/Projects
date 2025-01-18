""""
The Server for the Secure Chat application.

The Server manages all client connections and securely shares an AES key by appling RSA encryption.
It also relays encrypted messages between connected Clients.

Characteristics:
- RSA key exchange for secure AES key sharing
- AES encryption and decryption for secure communication
- Server logs all activity to a file
- Server operator can type messages in a console loop

Author: Jacob C
Date: 1/17/2025
"""

import socket
import threading
import logging
import os

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ---------------------
#  CONFIG & GLOBALS
# ---------------------
HOST = "localhost"
PORT = 5555

clients = {}  # Maps socket -> address
logging.basicConfig(filename="server.log", level=logging.INFO, format="%(asctime)s - %(message)s")

def log_activity(msg: str):
    """Print and log the activity."""
    print(msg)
    logging.info(msg)

# A single AES key for everyone
GROUP_AES_KEY = os.urandom(32)  # 256-bit key

def encrypt_with_group_key(plaintext: str) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(GROUP_AES_KEY), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv + ciphertext

def decrypt_with_group_key(ciphertext: bytes) -> str:
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(GROUP_AES_KEY), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext_bytes = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return plaintext_bytes.decode("utf-8", errors="replace")

# ---------------------
#  RSA KEYS
# ---------------------
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

def get_serialized_public_key() -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def encrypt_group_key_for_client(client_pub_pem: bytes) -> bytes:
    """Encrypt GROUP_AES_KEY with the client's RSA public key."""
    client_pubkey = serialization.load_pem_public_key(client_pub_pem)
    return client_pubkey.encrypt(
        GROUP_AES_KEY,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# ---------------------
#  BROADCAST
# ---------------------
def broadcast(ciphertext: bytes):
    """Send ciphertext to all connected clients."""
    for cli in clients:
        try:
            cli.send(ciphertext)
        except:
            pass

# ---------------------
#  CONSOLE LOOP
# ---------------------
def server_console():
    """
    Server operator can type messages here.
    Those messages are encrypted with GROUP_AES_KEY
    and broadcast to all clients.
    """
    while True:
        msg = input("Server> ")
        if msg.strip().lower() == "exit":
            print("Exiting server console loop (server still runs).")
            break
        if not msg:
            continue
        # Encrypt & broadcast
        enc = encrypt_with_group_key(f"SERVER BROADCAST: {msg}")
        broadcast(enc)

# ---------------------
#  CLIENT HANDLER
# ---------------------
def handle_client(client: socket.socket, address):
    """Perform RSA key exchange, then handle messages from client."""
    log_activity(f"New connection: {address}")
    try:
        # 1) Send server's public key
        client.send(get_serialized_public_key())

        # 2) Receive client's public key
        client_pub_pem = client.recv(2048)
        if not client_pub_pem:
            log_activity(f"No public key from {address}, closing.")
            return

        # 3) Encrypt & send group AES key
        enc_aes = encrypt_group_key_for_client(client_pub_pem)
        client.send(enc_aes)
        log_activity(f"Group AES key sent to {address}")

        # 4) Read messages in a loop
        while True:
            ciphertext = client.recv(4096)
            if not ciphertext:
                break
            # Decrypt for logs
            plaintext = decrypt_with_group_key(ciphertext)
            log_activity(f"Message from {address}: {plaintext}")

            # If user typed /ping
            if plaintext.strip().lower() == "/ping":
                # Respond to that client alone
                pong = encrypt_with_group_key("Server says: Pong!")
                client.send(pong)
            else:
                # Broadcast to all
                broadcast(ciphertext)

    except Exception as e:
        log_activity(f"Error with client {address}: {e}")
    finally:
        clients.pop(client, None)
        client.close()
        log_activity(f"Connection closed: {address}")

# ---------------------
#  SERVER MAIN
# ---------------------
def start_server():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((HOST, PORT))
    server_sock.listen()
    log_activity(f"Server started on {HOST}:{PORT}")

    # Start console loop in background
    threading.Thread(target=server_console, daemon=True).start()

    while True:
        cli, addr = server_sock.accept()
        clients[cli] = addr
        threading.Thread(target=handle_client, args=(cli, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()
