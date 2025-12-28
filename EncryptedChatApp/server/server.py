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

clients = []

def handle_client(client):
    while True:
        try:
            encrypted_msg = client.recv(1024).decode()
            msg = decrypt_message(encrypted_msg, key)
            print("Received:", msg)

            with open("server/chat_log.txt", "a") as log:
                log.write(msg + "\n")

            broadcast(msg, client)
        except:
            clients.remove(client)
            client.close()
            break

def broadcast(message, sender):
    encrypted = encrypt_message(message, key)
    for client in clients:
        if client != sender:
            client.send(encrypted.encode())

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

print("Server started... Waiting for connections")

while True:
    client, addr = server.accept()
    print(f"Connected with {addr}")
    clients.append(client)
    threading.Thread(target=handle_client, args=(client,)).start()
