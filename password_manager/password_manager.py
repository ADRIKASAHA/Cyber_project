import os
import json
import base64
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VAULT_FILE = "vault.json.enc"

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive AES key from master password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
        backend=default_backend()
    )
    return kdf.derive(master_password.encode())

def encrypt_data(data: dict, key: bytes) -> dict:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    plaintext = json.dumps(data).encode()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return {
        "salt": base64.b64encode(os.urandom(16)).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

def decrypt_data(container: dict, master_password: str) -> dict:
    salt = base64.b64decode(container["salt"])
    nonce = base64.b64decode(container["nonce"])
    ciphertext = base64.b64decode(container["ciphertext"])
    key = derive_key(master_password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode())

def init_vault(master_password: str):
    salt = os.urandom(16)
    key = derive_key(master_password, salt)
    data = {"entries": []}
    container = encrypt_data(data, key)
    container["salt"] = base64.b64encode(salt).decode()
    with open(VAULT_FILE, "w") as f:
        json.dump(container, f)
    print("Vault created.")

def load_vault(master_password: str) -> dict:
    with open(VAULT_FILE, "r") as f:
        container = json.load(f)
    return decrypt_data(container, master_password)

def save_vault(master_password: str, data: dict):
    salt = os.urandom(16)
    key = derive_key(master_password, salt)
    container = encrypt_data(data, key)
    container["salt"] = base64.b64encode(salt).decode()
    with open(VAULT_FILE, "w") as f:
        json.dump(container, f)

def add_entry(master_password: str, site: str, username: str, password: str):
    data = load_vault(master_password)
    data["entries"].append({"site": site, "username": username, "password": password})
    save_vault(master_password, data)
    print("Entry added.")

def search_entries(master_password: str, query: str):
    data = load_vault(master_password)
    for e in data["entries"]:
        if query.lower() in e["site"].lower() or query.lower() in e["username"].lower():
            print(e)

def main():
    print("Password Manager")
    choice = input("Choose: [init/add/search] ").strip().lower()
    master = getpass.getpass("Master password: ")

    if choice == "init":
        init_vault(master)
    elif choice == "add":
        site = input("Site: ")
        user = input("Username: ")
        pw = getpass.getpass("Password: ")
        add_entry(master, site, user, pw)
    elif choice == "search":
        q = input("Search query: ")
        search_entries(master, q)
    else:
        print("Unknown choice.")

if __name__ == "__main__":
    main()
