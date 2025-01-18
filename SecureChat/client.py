"""
Client for Secure Chat application.

The Client connects to a secure chat serve and sends/receives encrypted messages.
It performs RSA key exchange with the server to securely share an AES key for group communication.
It communicates sec
urely using AES encryption.

Characteristics:
- RSA key exchange for secure AES key sharing.
- AES encryption and decryption for secure communication.
- Background thread to receive broadcast messages.

Author: Jacob C
Date: 1/17/2025
"""

import socket
import threading
import os

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_with_group_key(aes_key: bytes, plaintext: str) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(plaintext.encode()) + encryptor.finalize()

def decrypt_with_group_key(aes_key: bytes, ciphertext: bytes) -> str:
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return decrypted.decode("utf-8", errors="replace")

def listen_for_messages(sock: socket.socket, aes_key: bytes):
    """Continuously receives broadcast messages from the server."""
    while True:
        try:
            ciphertext = sock.recv(4096)
            if not ciphertext:
                break
            plaintext = decrypt_with_group_key(aes_key, ciphertext)
            print(f"\n[Broadcast]: {plaintext}")
        except:
            break

def main():
    # 1) Connect to server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("localhost", 5555))

    # 2) Receive server's public key
    server_pub_pem = s.recv(2048)
    server_pubkey = serialization.load_pem_public_key(server_pub_pem)

    # 3) Generate our RSA key pair
    client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_public_key = client_private_key.public_key()

    # 4) Send our public key to server
    pub_pem = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    s.send(pub_pem)

    # 5) Receive the group AES key (encrypted with our public key)
    enc_key = s.recv(256)
    group_aes_key = client_private_key.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("Connected to server!")
    print("Type '/ping' for server response, or 'exit' to quit.")

    # 6) Start background thread to listen for messages
    threading.Thread(target=listen_for_messages, args=(s, group_aes_key), daemon=True).start()

    # 7) Main input loop
    while True:
        msg = input("You: ")
        if msg.strip().lower() == "exit":
            break
        ciphertext = encrypt_with_group_key(group_aes_key, msg)
        s.send(ciphertext)

    s.close()

if __name__ == "__main__":
    main()
