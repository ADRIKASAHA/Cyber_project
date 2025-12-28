from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import hashlib

def get_key(password):
    return hashlib.sha256(password.encode()).digest()

def encrypt_message(message, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padding = 16 - len(message) % 16
    message += chr(padding) * padding
    encrypted = cipher.encrypt(message.encode())
    return base64.b64encode(iv + encrypted).decode()

def decrypt_message(ciphertext, key):
    data = base64.b64decode(ciphertext)
    iv = data[:16]
    encrypted = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted).decode()
    padding = ord(decrypted[-1])
    return decrypted[:-padding]
