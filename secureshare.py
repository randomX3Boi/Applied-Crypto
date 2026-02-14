import os
import json
import base64
from pathlib import Path
from getpass import getpass

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Signature import pss

# ==================================================
# DIRECTORY STRUCTURE
# ==================================================
DATA_DIR = Path("data")
SERVER_DIR = DATA_DIR / "server"
STORAGE_DIR = SERVER_DIR / "storage"
CLIENTS_DIR = DATA_DIR / "clients"

USERS_FILE = SERVER_DIR / "users.json"
FILES_FILE = SERVER_DIR / "files.json"

DATA_DIR.mkdir(exist_ok=True)
SERVER_DIR.mkdir(exist_ok=True)
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
CLIENTS_DIR.mkdir(exist_ok=True)

# ==================================================
# UTILITY FUNCTIONS
# ==================================================
def b64e(b): return base64.b64encode(b).decode()
def b64d(s): return base64.b64decode(s.encode())

def load_json(path):
    if not path.exists():
        return {}
    return json.loads(path.read_text())

def save_json(path, data):
    path.write_text(json.dumps(data, indent=2))

def user_dir(username):
    d = CLIENTS_DIR / username
    d.mkdir(parents=True, exist_ok=True)
    return d

# ==================================================
# PRIVATE KEY PROTECTION
# ==================================================
PBKDF2_ITERS = 200000

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=32, count=PBKDF2_ITERS, hmac_hash_module=SHA256)

def encrypt_private_key(private_pem, password):
    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(private_pem)
    return salt + cipher.nonce + tag + ciphertext

def decrypt_private_key(blob, password):
    salt = blob[:16]
    nonce = blob[16:32]
    tag = blob[32:48]
    ciphertext = blob[48:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def load_private_key(username):
    path = user_dir(username) / "private.pem.enc"
    if not path.exists():
        raise FileNotFoundError("Private key not found.")
    password = getpass("Password: ")
    blob = path.read_bytes()
    try:
        private_pem = decrypt_private_key(blob, password)
    except ValueError:
        raise ValueError("Wrong password or key file tampered.")
    return RSA.import_key(private_pem)

# ==================================================
# DIGITAL SIGNATURES (RSA-PSS)
# ==================================================
def sign_data(private_key, data):
    h = SHA256.new(data)
    return pss.new(private_key).sign(h)

def verify_signature(public_key, data, signature):
    h = SHA256.new(data)
    try:
        pss.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# ==================================================
# REGISTER USER
# ==================================================
def register():
    username = input("Username: ").strip()
    users = load_json(USERS_FILE)

    if username in users:
        print("User already exists.\n")
        return

    password = getpass("Set password: ")
    if len(password) < 6:
        print("Password too short.\n")
        return

    key = RSA.generate(2048)
    private_pem = key.export_key()
    public_pem = key.publickey().export_key().decode()

    encrypted_private = encrypt_private_key(private_pem, password)
    (user_dir(username) / "private.pem.enc").write_bytes(encrypted_private)

    users[username] = {"public_key": public_pem}
    save_json(USERS_FILE, users)

    print("User registered successfully.\n")

# ==================================================
# UPLOAD FILE
# ==================================================
def upload():
    username = input("Your username: ").strip()
    filepath = input("File path: ").strip()

    if not Path(filepath).exists():
        print("File does not exist.\n")
        return

    users = load_json(USERS_FILE)
    if username not in users:
        print("User not found.\n")
        return

    acl_input = input("Grant access to (comma separated usernames): ")
    acl = {u.strip() for u in acl_input.split(",") if u.strip()}
    acl.add(username)

    for u in acl:
        if u not in users:
            print(f"User '{u}' does not exist.\n")
            return

    file_key = get_random_bytes(32)
    plaintext = Path(filepath).read_bytes()

    cipher = AES.new(file_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    nonce = cipher.nonce

    wrapped_keys = {}
    for u in acl:
        pub = RSA.import_key(users[u]["public_key"])
        wrapped = PKCS1_OAEP.new(pub, hashAlgo=SHA256).encrypt(file_key)
        wrapped_keys[u] = b64e(wrapped)

    try:
        private_key = load_private_key(username)
    except Exception as e:
        print(f"{e}\n")
        return

    signature = sign_data(private_key, ciphertext + nonce + tag)

    files = load_json(FILES_FILE)
    file_id = str(int(max(files.keys(), default="0")) + 1)

    cipher_path = STORAGE_DIR / f"file_{file_id}.bin"
    cipher_path.write_bytes(ciphertext)

    files[file_id] = {
        "owner": username,
        "filename": os.path.basename(filepath),
        "cipher_path": str(cipher_path),
        "nonce": b64e(nonce),
        "tag": b64e(tag),
        "signature": b64e(signature),
        "acl": wrapped_keys
    }

    save_json(FILES_FILE, files)

    print(f"File uploaded successfully. ID = {file_id}\n")

# ==================================================
# LIST FILES
# ==================================================
def list_files():
    username = input("Your username: ").strip()
    files = load_json(FILES_FILE)

    print("\n==== Accessible Files ====")
    found = False

    for fid, meta in files.items():
        if username in meta.get("acl", {}):
            found = True
            print(f"\nFile ID: {fid}")
            print(f"  Filename : {meta['filename']}")
            print(f"  Owner    : {meta['owner']}")

    if not found:
        print("No files available.")
    print()

# ==================================================
# DOWNLOAD FILE
# ==================================================
def download():
    username = input("Your username: ").strip()
    file_id = input("File ID: ").strip()

    users = load_json(USERS_FILE)
    files = load_json(FILES_FILE)

    if file_id not in files:
        print("File not found.\n")
        return

    meta = files[file_id]

    if username not in meta["acl"]:
        print("Access denied.\n")
        return

    ciphertext = Path(meta["cipher_path"]).read_bytes()
    nonce = b64d(meta["nonce"])
    tag = b64d(meta["tag"])
    signature = b64d(meta["signature"])

    owner_pub = RSA.import_key(users[meta["owner"]]["public_key"])

    if not verify_signature(owner_pub, ciphertext + nonce + tag, signature):
        print("Signature verification failed.\n")
        return

    print("Signature verified.")

    try:
        private_key = load_private_key(username)
    except Exception as e:
        print(f"{e}\n")
        return

    wrapped_key = b64d(meta["acl"][username])
    file_key = PKCS1_OAEP.new(private_key, hashAlgo=SHA256).decrypt(wrapped_key)

    aes = AES.new(file_key, AES.MODE_GCM, nonce=nonce)
    plaintext = aes.decrypt_and_verify(ciphertext, tag)

    downloads_dir = user_dir(username) / "downloads"
    downloads_dir.mkdir(exist_ok=True)

    output_path = downloads_dir / meta["filename"]

    counter = 1
    while output_path.exists():
        stem = output_path.stem
        suffix = output_path.suffix
        output_path = downloads_dir / f"{stem}_{counter}{suffix}"
        counter += 1

    output_path.write_bytes(plaintext)

    print(f"File saved to: {output_path}\n")

# ==================================================
# MENU
# ==================================================
def main():
    while True:
        print("==== SecureShare ====")
        print("1. Register user")
        print("2. Upload file")
        print("3. List my files")
        print("4. Download file")
        print("5. Exit")

        choice = input("Select: ")

        if choice == "1":
            register()
        elif choice == "2":
            upload()
        elif choice == "3":
            list_files()
        elif choice == "4":
            download()
        elif choice == "5":
            print("Goodbye.")
            break
        else:
            print("Invalid option.\n")

if __name__ == "__main__":
    main()
