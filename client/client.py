"""
CLIENT APPLICATION

Implements:
- RSA keypair generation
- Password-protected private key storage
- Hybrid encryption (AES-GCM + RSA-OAEP)
- RSA-PSS digital signatures
- Multi-user ACL
- Secure ACL update (re-keying)
- Session-based login
"""

import json
import base64
import uuid
import time
from pathlib import Path
from getpass import getpass

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Signature import pss


# ==================================================
# PATH CONFIGURATION
# ==================================================

BASE_DIR = Path(__file__).parent.resolve()
USERS_DIR = BASE_DIR / "users"

SERVER_DIR = (BASE_DIR.parent / "server").resolve()
REQUESTS_DIR = SERVER_DIR / "requests"
RESPONSES_DIR = SERVER_DIR / "responses"

PBKDF2_ITERS = 200000


# ==================================================
# SESSION STATE
# ==================================================

CURRENT_USER = None
CURRENT_PRIVATE_KEY = None


# ==================================================
# HELPERS
# ==================================================

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())


def user_dir(username: str) -> Path:
    d = USERS_DIR / username
    d.mkdir(parents=True, exist_ok=True)
    return d


def send_request(payload: dict, timeout_s=10):
    if not REQUESTS_DIR.exists():
        return {"status": "error", "message": "Server not running"}

    req_id = str(uuid.uuid4())
    req_path = REQUESTS_DIR / f"{req_id}.json"
    resp_path = RESPONSES_DIR / f"{req_id}.json"

    req_path.write_text(json.dumps(payload))

    start = time.time()
    while not resp_path.exists():
        if time.time() - start > timeout_s:
            return {"status": "error", "message": "Timeout"}
        time.sleep(0.05)

    response = json.loads(resp_path.read_text())
    resp_path.unlink()
    return response


# ==================================================
# PRIVATE KEY PROTECTION
# ==================================================

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=32,
                  count=PBKDF2_ITERS,
                  hmac_hash_module=SHA256)


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
    password = getpass("Password: ")
    private_pem = decrypt_private_key(path.read_bytes(), password)
    return RSA.import_key(private_pem)


# ==================================================
# SIGNATURES
# ==================================================

def sign_blob(private_key, data):
    h = SHA256.new(data)
    return pss.new(private_key).sign(h)


def verify_blob(public_key, data, signature):
    h = SHA256.new(data)
    try:
        pss.new(public_key).verify(h, signature)
        return True
    except:
        return False


# ==================================================
# REGISTER
# ==================================================

def register():
    username = input("Username (0 to return): ").strip()
    if username == "0":
        return

    p1 = getpass("Set password: ")
    p2 = getpass("Confirm password: ")

    if p1 != p2:
        print("Passwords do not match.")
        return

    key = RSA.generate(2048)

    private_pem = key.export_key()
    public_pem = key.publickey().export_key().decode()

    (user_dir(username) / "private.pem.enc").write_bytes(
        encrypt_private_key(private_pem, p1)
    )

    resp = send_request({
        "action": "register",
        "username": username,
        "public_key": public_pem
    })

    if resp.get("status") == "ok":
        print("Account created.")
    else:
        print(resp.get("message"))


# ==================================================
# LOGIN / LOGOUT
# ==================================================

def login():
    global CURRENT_USER, CURRENT_PRIVATE_KEY

    username = input("Username (0 to return): ").strip()
    if username == "0":
        return

    try:
        key = load_private_key(username)
    except Exception as e:
        print("Login failed:", e)
        return

    CURRENT_USER = username
    CURRENT_PRIVATE_KEY = key
    print("Login successful.")


def logout():
    global CURRENT_USER, CURRENT_PRIVATE_KEY
    CURRENT_USER = None
    CURRENT_PRIVATE_KEY = None
    print("Logged out.")


# ==================================================
# UPLOAD
# ==================================================

def upload():
    if not CURRENT_USER:
        print("Login first.")
        return

    path = input("File path: ").strip()
    if not Path(path).exists():
        print("File not found.")
        return

    acl_input = input("Grant access to (comma-separated): ").strip()
    recipients = {u.strip() for u in acl_input.split(",") if u.strip()}
    recipients.add(CURRENT_USER)

    keys_resp = send_request({
        "action": "get_public_keys",
        "usernames": list(recipients)
    })

    if keys_resp.get("missing"):
        print("Unknown users:", keys_resp["missing"])
        return

    plaintext = Path(path).read_bytes()
    file_key = get_random_bytes(32)

    aes = AES.new(file_key, AES.MODE_GCM)
    ciphertext, tag = aes.encrypt_and_digest(plaintext)
    nonce = aes.nonce

    acl = {}
    for user, pub_pem in keys_resp["keys"].items():
        pub = RSA.import_key(pub_pem)
        wrapped = PKCS1_OAEP.new(pub, hashAlgo=SHA256).encrypt(file_key)
        acl[user] = b64e(wrapped)

    signature = sign_blob(CURRENT_PRIVATE_KEY,
                          ciphertext + nonce + tag)

    resp = send_request({
        "action": "upload",
        "owner": CURRENT_USER,
        "filename": Path(path).name,
        "ciphertext": b64e(ciphertext),
        "nonce": b64e(nonce),
        "tag": b64e(tag),
        "signature": b64e(signature),
        "acl": acl
    })

    print(resp.get("message", "Uploaded."))


# ==================================================
# DOWNLOAD
# ==================================================

def download():
    if not CURRENT_USER:
        print("Login first.")
        return

    list_resp = send_request({
        "action": "list",
        "username": CURRENT_USER
    })

    files = list_resp.get("files", {})
    if not files:
        print("No accessible files.")
        return

    for fid, meta in files.items():
        print(f"{fid} -> {meta['filename']} (Owner: {meta['owner']})")

    file_id = input("File ID: ").strip()

    dl_resp = send_request({
        "action": "download",
        "file_id": file_id,
        "requester": CURRENT_USER
    })

    if dl_resp.get("status") != "ok":
        print(dl_resp.get("message"))
        return

    meta = dl_resp["meta"]

    ciphertext = b64d(dl_resp["ciphertext"])
    nonce = b64d(meta["nonce"])
    tag = b64d(meta["tag"])
    signature = b64d(meta["signature"])

    owner = meta["owner"]

    owner_key_resp = send_request({
        "action": "get_public_keys",
        "usernames": [owner]
    })

    owner_pub = RSA.import_key(owner_key_resp["keys"][owner])

    if not verify_blob(owner_pub,
                       ciphertext + nonce + tag,
                       signature):
        print("Signature invalid.")
        return

    wrapped_key = b64d(meta["acl"][CURRENT_USER])
    file_key = PKCS1_OAEP.new(
        CURRENT_PRIVATE_KEY,
        hashAlgo=SHA256
    ).decrypt(wrapped_key)

    aes = AES.new(file_key, AES.MODE_GCM, nonce=nonce)
    plaintext = aes.decrypt_and_verify(ciphertext, tag)

    output = user_dir(CURRENT_USER) / meta["filename"]
    output.write_bytes(plaintext)

    print("File saved to:", output)


# ==================================================
# UPDATE ACL (REKEY)
# ==================================================

def update_acl():
    if not CURRENT_USER:
        print("Login first.")
        return

    # Get files accessible to user
    list_resp = send_request({
        "action": "list",
        "username": CURRENT_USER
    })

    files = list_resp.get("files", {})
    owned = {fid: meta for fid, meta in files.items() 
            if meta["owner"] == CURRENT_USER}

    if not owned:
        print("You do not own any files.")
        return

    print("\nFiles You Own:")
    for fid, meta in owned.items():
        print(f"\nFile ID: {fid}")
        print(f"Filename: {meta['filename']}")

    file_id = input("\nFile ID to modify (0 to cancel): ").strip()
    if file_id == "0":
        return

    if file_id not in owned:
        print("Invalid File ID.")
        return

    # Fetch full metadata
    dl_resp = send_request({
        "action": "download",
        "file_id": file_id,
        "requester": CURRENT_USER
    })

    meta = dl_resp["meta"]

    current_acl = set(meta["acl"].keys())

    print("\nCurrent ACL:", ", ".join(sorted(current_acl)))

    new_acl_input = input("New ACL (comma-separated): ").strip()
    new_recipients = {u.strip() for u in new_acl_input.split(",") if u.strip()}
    new_recipients.add(CURRENT_USER)

    print("\nNew ACL:", ", ".join(sorted(new_recipients)))

    added = new_recipients - current_acl
    removed = current_acl - new_recipients

    print("\nChanges:")
    print("Added:", ", ".join(added) if added else "(none)")
    print("Removed:", ", ".join(removed) if removed else "(none)")

    confirm = input("\nConfirm update? (y/n): ").strip().lower()
    if confirm != "y":
        print("ACL update cancelled.")
        return

    # Get public keys
    keys_resp = send_request({
        "action": "get_public_keys",
        "usernames": list(new_recipients)
    })

    if keys_resp.get("missing"):
        print("Unknown users:", keys_resp["missing"])
        return

    # Decrypt old file
    ciphertext = b64d(dl_resp["ciphertext"])
    nonce = b64d(meta["nonce"])
    tag = b64d(meta["tag"])

    wrapped_key = b64d(meta["acl"][CURRENT_USER])
    old_key = PKCS1_OAEP.new(
        CURRENT_PRIVATE_KEY,
        hashAlgo=SHA256
    ).decrypt(wrapped_key)

    aes = AES.new(old_key, AES.MODE_GCM, nonce=nonce)
    plaintext = aes.decrypt_and_verify(ciphertext, tag)

    # Generate new AES key
    new_key = get_random_bytes(32)

    aes = AES.new(new_key, AES.MODE_GCM)
    new_ciphertext, new_tag = aes.encrypt_and_digest(plaintext)
    new_nonce = aes.nonce

    # Wrap new key for new ACL
    new_acl = {}
    for user, pub_pem in keys_resp["keys"].items():
        pub = RSA.import_key(pub_pem)
        wrapped = PKCS1_OAEP.new(pub,hashAlgo=SHA256).encrypt(new_key)
        new_acl[user] = b64e(wrapped)

    new_sig = sign_blob(CURRENT_PRIVATE_KEY,
                        new_ciphertext + new_nonce + new_tag)

    resp = send_request({
        "action": "update_acl",
        "file_id": file_id,
        "requester": CURRENT_USER,
        "ciphertext": b64e(new_ciphertext),
        "nonce": b64e(new_nonce),
        "tag": b64e(new_tag),
        "signature": b64e(new_sig),
        "acl": new_acl
    })

    print(resp.get("message", "ACL updated."))


# ==================================================
# MAIN MENU
# ==================================================

def main():
    while True:
        print("\n==== Client Menu ====")

        if CURRENT_USER is None:
            print("1 Register")
            print("2 Login")
            print("0 Exit")

            choice = input("Select: ").strip()

            if choice == "1":
                register()
            elif choice == "2":
                login()
            elif choice == "0":
                break
            else:
                print("Invalid option.")

        else:
            print("Logged in as:", CURRENT_USER)
            print("1 Upload")
            print("2 Download")
            print("3 Update ACL")
            print("4 Logout")
            print("0 Exit")

            choice = input("Select: ").strip()

            if choice == "1":
                upload()
            elif choice == "2":
                download()
            elif choice == "3":
                update_acl()
            elif choice == "4":
                logout()
            elif choice == "0":
                break
            else:
                print("Invalid option.")


if __name__ == "__main__":
    main()