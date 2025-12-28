import sys
import os

# Add project root directory to Python path
sys.path.append(r"D:\job\Syntecxhub\cyber_project\EncryptedChatApp")

import socket
import threading
from crypto.crypto_utils import encrypt_message, decrypt_message, get_key



HOST = '127.0.0.1'
PORT = 5555
PASSWORD = "sharedsecret"
key = get_key(PASSWORD)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

def receive():
    while True:
        try:
            encrypted_msg = client.recv(1024).decode()
            print(decrypt_message(encrypted_msg, key))
        except:
            break

def send():
    while True:
        msg = input()
        if msg.strip() == "":
            continue   # ignore empty input
        encrypted = encrypt_message(msg, key)
        client.send(encrypted.encode())


threading.Thread(target=receive).start()
threading.Thread(target=send).start()
