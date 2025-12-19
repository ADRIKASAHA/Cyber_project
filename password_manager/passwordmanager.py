#!/usr/bin/env python3
import os
import json
import base64
import argparse
import getpass
from datetime import datetime
from typing import Dict, Any, List

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# -------------------------
# Config
# -------------------------
FORMAT_VERSION = 1
DEFAULT_DB_PATH = "vault.json.enc"
PBKDF2_ITERATIONS = 200_000  # increase if your machine is fast

# -------------------------
# Key derivation and crypto
# -------------------------
def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from master password and salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(master_password.encode("utf-8"))

def encrypt_store(plaintext_json: str, key: bytes) -> Dict[str, Any]:
    """Encrypt JSON plaintext with AES-GCM and return storage record."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce recommended for GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext_json.encode("utf-8"), associated_data=None)
    return {
        "version": FORMAT_VERSION,
        "kdf": {"type": "pbkdf2-sha256", "iterations": PBKDF2_ITERATIONS},
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "data": base64.b64encode(ciphertext).decode("utf-8"),
    }

def decrypt_store(record: Dict[str, Any], key: bytes) -> str:
    """Decrypt storage record to JSON plaintext."""
    aesgcm = AESGCM(key)
    nonce = base64.b64decode(record["nonce"])
    ciphertext = base64.b64decode(record["data"])
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext.decode("utf-8")

# -------------------------
# Vault I/O
# -------------------------
def create_new_vault(db_path: str, master_password: str) -> Dict[str, Any]:
    """Create a new empty vault with fresh salt and encrypted payload."""
    salt = os.urandom(16)
    key = derive_key(master_password, salt)
    empty_store = {"entries": [], "meta": {"created_at": datetime.utcnow().isoformat()}}
    record = encrypt_store(json.dumps(empty_store, ensure_ascii=False), key)
    container = {"salt": base64.b64encode(salt).decode("utf-8"), "record": record}
    with open(db_path, "w", encoding="utf-8") as f:
        json.dump(container, f, indent=2)
    return empty_store

def load_vault(db_path: str, master_password: str) -> Dict[str, Any]:
    """Load and decrypt the vault using the master password."""
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Vault not found: {db_path}")
    with open(db_path, "r", encoding="utf-8") as f:
        container = json.load(f)
    salt = base64.b64decode(container["salt"])
    key = derive_key(master_password, salt)
    plaintext_json = decrypt_store(container["record"], key)
    return json.loads(plaintext_json)

def save_vault(db_path: str, master_password: str, store: Dict[str, Any]) -> None:
    """Encrypt and write the vault back to disk."""
    with open(db_path, "r", encoding="utf-8") as f:
        container = json.load(f)
    salt = base64.b64decode(container["salt"])
    key = derive_key(master_password, salt)
    record = encrypt_store(json.dumps(store, ensure_ascii=False), key)
    container["record"] = record
    with open(db_path, "w", encoding="utf-8") as f:
        json.dump(container, f, indent=2)

# -------------------------
# Entry management
# -------------------------
def add_entry(store: Dict[str, Any], site: str, username: str, password: str, notes: str = "") -> None:
    """Add a credential entry (unique by site+username)."""
    entries = store["entries"]
    for e in entries:
        if e["site"].lower() == site.lower() and e["username"] == username:
            raise ValueError("Entry already exists for this site and username.")
    entries.append({
        "site": site,
        "username": username,
        "password": password,
        "notes": notes,
        "updated_at": datetime.utcnow().isoformat(),
    })
    store["meta"]["updated_at"] = datetime.utcnow().isoformat()

def find_entries(store: Dict[str, Any], query: str) -> List[Dict[str, Any]]:
    """Search entries by substring in site, username, or notes."""
    q = query.lower()
    return [
        e for e in store["entries"]
        if q in e["site"].lower() or q in e["username"].lower() or q in e.get("notes", "").lower()
    ]

def get_entry(store: Dict[str, Any], site: str, username: str) -> Dict[str, Any]:
    """Retrieve a specific entry by site and username."""
    for e in store["entries"]:
        if e["site"].lower() == site.lower() and e["username"] == username:
            return e
    raise KeyError("Entry not found.")

def delete_entry(store: Dict[str, Any], site: str, username: str) -> None:
    """Delete an entry by site and username."""
    before = len(store["entries"])
    store["entries"] = [e for e in store["entries"] if not (e["site"].lower() == site.lower() and e["username"] == username)]
    after = len(store["entries"])
    if before == after:
        raise KeyError("Entry not found.")
    store["meta"]["updated_at"] = datetime.utcnow().isoformat()

# -------------------------
# CLI
# -------------------------
def prompt_master_password(confirm: bool = False) -> str:
    """Securely prompt for master password."""
    pw = getpass.getpass("Master password: ")
    if confirm:
        pw2 = getpass.getpass("Confirm master password: ")
        if pw != pw2:
            raise ValueError("Master passwords do not match.")
    if len(pw) < 8:
        raise ValueError("Master password must be at least 8 characters.")
    return pw

def cmd_init(args):
    master = prompt_master_password(confirm=True)
    if os.path.exists(args.db):
        raise FileExistsError(f"File already exists: {args.db}")
    create_new_vault(args.db, master)
    print(f"Vault created: {args.db}")

def cmd_add(args):
    master = prompt_master_password()
    try:
        store = load_vault(args.db, master)
        add_entry(store, args.site, args.username, args.password, notes=args.notes or "")
        save_vault(args.db, master, store)
        print("Entry added.")
    except Exception as e:
        print(f"Error: {e}")

def cmd_get(args):
    master = prompt_master_password()
    try:
        store = load_vault(args.db, master)
        entry = get_entry(store, args.site, args.username)
        print(f"Site: {entry['site']}")
        print(f"Username: {entry['username']}")
        print(f"Password: {entry['password']}")
        if entry.get("notes"):
            print(f"Notes: {entry['notes']}")
    except Exception as e:
        print(f"Error: {e}")

def cmd_search(args):
    master = prompt_master_password()
    try:
        store = load_vault(args.db, master)
        results = find_entries(store, args.query)
        if not results:
            print("No matches.")
            return
        for i, e in enumerate(results, 1):
            label = "(notes)" if e.get("notes") else ""
            print(f"[{i}] {e['site']} | {e['username']} | {label}")
    except Exception as e:
        print(f"Error: {e}")

def cmd_delete(args):
    master = prompt_master_password()
    try:
        store = load_vault(args.db, master)
        delete_entry(store, args.site, args.username)
        save_vault(args.db, master, store)
        print("Entry deleted.")
    except Exception as e:
        print(f"Error: {e}")

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local AES-GCM encrypted password manager")
    parser.add_argument("--db", default=DEFAULT_DB_PATH, help="Path to encrypted vault file")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Initialize a new encrypted vault")
    p_init.set_defaults(func=cmd_init)

    p_add = sub.add_parser("add", help="Add a credential entry")
    p_add.add_argument("--site", required=True, help="Site or service name")
    p_add.add_argument("--username", required=True, help="Username or email")
    p_add.add_argument("--password", required=True, help="Password (paste or type)")
    p_add.add_argument("--notes", help="Optional notes")
    p_add.set_defaults(func=cmd_add)

    p_get = sub.add_parser("get", help="Retrieve an entry")
    p_get.add_argument("--site", required=True)
    p_get.add_argument("--username", required=True)
    p_get.set_defaults(func=cmd_get)

    p_search = sub.add_parser("search", help="Search entries")
    p_search.add_argument("--query", required=True, help="Substring to search for")
    p_search.set_defaults(func=cmd_search)

    p_del = sub.add_parser("delete", help="Delete an entry")
    p_del.add_argument("--site", required=True)
    p_del.add_argument("--username", required=True)
    p_del.set_defaults(func=cmd_delete)

    return parser

def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
