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
# DIRECTORY STRUCTURE (Server vs Client separation)
# ==================================================
DATA_DIR = Path("data")
SERVER_DIR = DATA_DIR / "server"      # Server-side storage (public data only)
STORAGE_DIR = SERVER_DIR / "storage" # Encrypted file contents
CLIENTS_DIR = DATA_DIR / "clients"   # Client-side local secrets

USERS_FILE = SERVER_DIR / "users.json"  # username -> public key
FILES_FILE = SERVER_DIR / "files.json"  # file metadata + ACL

# Auto-create required folders
DATA_DIR.mkdir(exist_ok=True)
SERVER_DIR.mkdir(exist_ok=True)
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
CLIENTS_DIR.mkdir(exist_ok=True)


# ==================================================
# UTILITY FUNCTIONS
# ==================================================
def b64e(b): return base64.b64encode(b).decode()  # bytes -> base64 string
def b64d(s): return base64.b64decode(s.encode()) # base64 string -> bytes

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
# PRIVATE KEY PROTECTION (Client-side only)
# ==================================================
PBKDF2_ITERS = 200000  # Password hardening

def derive_key(password, salt):
    # Derive 256-bit key from password
    return PBKDF2(password, salt, dkLen=32, count=PBKDF2_ITERS, hmac_hash_module=SHA256)

def encrypt_private_key(private_pem, password):
    # Encrypt RSA private key using AES-GCM
    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(private_pem)
    return salt + cipher.nonce + tag + ciphertext

def decrypt_private_key(blob, password):
    # Decrypt RSA private key blob
    salt = blob[:16]
    nonce = blob[16:32]
    tag = blob[32:48]
    ciphertext = blob[48:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def load_private_key(username):
    # Load and decrypt local private key
    path = user_dir(username) / "private.pem.enc"
    if not path.exists():
        raise FileNotFoundError("Private key not found.")
    password = getpass("Password: ")
    blob = path.read_bytes()
    private_pem = decrypt_private_key(blob, password)
    return RSA.import_key(private_pem)


# ==================================================
# DIGITAL SIGNATURES (RSA-PSS)
# ==================================================
def sign_data(private_key, data):
    # Sign SHA256 hash of data
    h = SHA256.new(data)
    return pss.new(private_key).sign(h)

def verify_signature(public_key, data, signature):
    # Verify RSA-PSS signature
    h = SHA256.new(data)
    try:
        pss.new(public_key).verify(h, signature)
        return True
    except:
        return False


# ==================================================
# REGISTER USER
# ==================================================
def register():
    # Generate RSA keypair locally
    username = input("Username: ").strip()
    users = load_json(USERS_FILE)

    if username in users:
        print("User already exists.\n")
        return

    password = getpass("Set password: ")

    key = RSA.generate(2048)
    private_pem = key.export_key()
    public_pem = key.publickey().export_key().decode()

    # Store encrypted private key locally
    encrypted_private = encrypt_private_key(private_pem, password)
    (user_dir(username) / "private.pem.enc").write_bytes(encrypted_private)

    # Store public key on server
    users[username] = {"public_key": public_pem}
    save_json(USERS_FILE, users)

    print("User registered successfully.\n")


# ==================================================
# UPLOAD FILE (Hybrid Encryption)
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

    # Build Access Control List
    acl_input = input("Grant access to (comma separated usernames): ")
    acl = {u.strip() for u in acl_input.split(",") if u.strip()}
    acl.add(username)  # Owner always included

    for u in acl:
        if u not in users:
            print(f"User '{u}' does not exist.\n")
            return

    # Generate AES-256 file key
    file_key = get_random_bytes(32)
    plaintext = Path(filepath).read_bytes()

    # Encrypt file with AES-GCM
    cipher = AES.new(file_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    nonce = cipher.nonce

    # Wrap AES key for each user using RSA-OAEP
    wrapped_keys = {}
    for u in acl:
        pub = RSA.import_key(users[u]["public_key"])
        wrapped = PKCS1_OAEP.new(pub, hashAlgo=SHA256).encrypt(file_key)
        wrapped_keys[u] = b64e(wrapped)

    # Sign encrypted content
    private_key = load_private_key(username)
    signature = sign_data(private_key, ciphertext + nonce + tag)

    # Store ciphertext on server
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

    for fid, meta in files.items():
        if username in meta.get("acl", {}):
            print(f"\nFile ID: {fid}")
            print(f"  Filename : {meta['filename']}")
            print(f"  Owner    : {meta['owner']}")
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

    # Enforce ACL
    if username not in meta["acl"]:
        print("Access denied.\n")
        return

    # Load ciphertext and metadata
    ciphertext = Path(meta["cipher_path"]).read_bytes()
    nonce = b64d(meta["nonce"])
    tag = b64d(meta["tag"])
    signature = b64d(meta["signature"])

    # Verify uploader signature before decrypting
    owner_pub = RSA.import_key(users[meta["owner"]]["public_key"])
    if not verify_signature(owner_pub, ciphertext + nonce + tag, signature):
        print("Signature verification failed.\n")
        return

    # Load private key and unwrap AES key
    private_key = load_private_key(username)
    wrapped_key = b64d(meta["acl"][username])
    file_key = PKCS1_OAEP.new(private_key, hashAlgo=SHA256).decrypt(wrapped_key)

    # Decrypt file
    aes = AES.new(file_key, AES.MODE_GCM, nonce=nonce)
    plaintext = aes.decrypt_and_verify(ciphertext, tag)

    # Save to client downloads folder
    downloads_dir = user_dir(username) / "downloads"
    downloads_dir.mkdir(exist_ok=True)

    output_path = downloads_dir / meta["filename"]
    output_path.write_bytes(plaintext)

    print(f"File saved to: {output_path}\n")


# ==================================================
# MAIN MENU
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
            break
        else:
            print("Invalid option.\n")

if __name__ == "__main__":
    main()
