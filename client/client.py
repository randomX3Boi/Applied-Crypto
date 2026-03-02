"""
CLIENT APPLICATION

Implements:
- RSA keypair generation
- Password-protected private key storage
- Hybrid encryption (AES-GCM + RSA-OAEP)
- RSA-PSS signatures
- Session-authenticated requests
- ACL update with secure re-keying
- ACL-authorized file modification workflow
"""

import base64
import json
import time
import uuid
from getpass import getpass
from pathlib import Path

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
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
CURRENT_SESSION_TOKEN = None


# ==================================================
# HELPERS
# ==================================================

def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("utf-8")


def b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("utf-8"))


def user_dir(username: str) -> Path:
    directory = USERS_DIR / username
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def send_request(payload: dict, timeout_s: int = 10):
    if not REQUESTS_DIR.exists():
        return {"status": "error", "message": "Server not running"}

    request_id = str(uuid.uuid4())
    req_path = REQUESTS_DIR / f"{request_id}.json"
    resp_path = RESPONSES_DIR / f"{request_id}.json"

    req_path.write_text(json.dumps(payload), encoding="utf-8")

    start = time.time()
    while not resp_path.exists():
        if time.time() - start > timeout_s:
            return {"status": "error", "message": "Timeout"}
        time.sleep(0.05)

    response = json.loads(resp_path.read_text(encoding="utf-8"))
    resp_path.unlink()
    return response


def with_session(payload: dict) -> dict:
    if CURRENT_SESSION_TOKEN:
        payload["session_token"] = CURRENT_SESSION_TOKEN
    return payload


# ==================================================
# PRIVATE KEY PROTECTION
# ==================================================

def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(
        password,
        salt,
        dkLen=32,
        count=PBKDF2_ITERS,
        hmac_hash_module=SHA256,
    )


def encrypt_private_key(private_pem: bytes, password: str) -> bytes:
    salt = get_random_bytes(16)
    key = derive_key(password, salt)

    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(private_pem)

    return salt + cipher.nonce + tag + ciphertext


def decrypt_private_key(blob: bytes, password: str) -> bytes:
    salt = blob[:16]
    nonce = blob[16:32]
    tag = blob[32:48]
    ciphertext = blob[48:]

    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    return cipher.decrypt_and_verify(ciphertext, tag)


def load_private_key(username: str):
    encrypted_path = user_dir(username) / "private.pem.enc"
    password = getpass("Password: ")
    private_pem = decrypt_private_key(encrypted_path.read_bytes(), password)
    return RSA.import_key(private_pem)


# ==================================================
# SIGNATURES
# ==================================================

def sign_blob(private_key, data: bytes) -> bytes:
    digest = SHA256.new(data)
    return pss.new(private_key).sign(digest)


def verify_blob(public_key, data: bytes, signature: bytes) -> bool:
    digest = SHA256.new(data)
    try:
        pss.new(public_key).verify(digest, signature)
        return True
    except (ValueError, TypeError):
        return False


# ==================================================
# REGISTER
# ==================================================

def register():
    username = input("Username (0 to return): ").strip()
    if username == "0":
        return

    password_1 = getpass("Set password: ")
    password_2 = getpass("Confirm password: ")

    if password_1 != password_2:
        print("Passwords do not match.")
        return

    keypair = RSA.generate(2048)

    private_pem = keypair.export_key()
    public_pem = keypair.publickey().export_key().decode("utf-8")

    (user_dir(username) / "private.pem.enc").write_bytes(
        encrypt_private_key(private_pem, password_1)
    )

    response = send_request(
        {
            "action": "register",
            "username": username,
            "public_key": public_pem,
        }
    )

    if response.get("status") == "ok":
        print("Account created.")
    else:
        print(response.get("message", "Registration failed"))


# ==================================================
# LOGIN / LOGOUT
# ==================================================

def login():
    global CURRENT_USER, CURRENT_PRIVATE_KEY, CURRENT_SESSION_TOKEN

    username = input("Username (0 to return): ").strip()
    if username == "0":
        return

    try:
        private_key = load_private_key(username)
    except Exception as exc:
        print("Login failed:", exc)
        return

    challenge_resp = send_request(
        {
            "action": "login_challenge",
            "username": username,
        }
    )

    if challenge_resp.get("status") != "ok":
        print(challenge_resp.get("message", "Unable to start login"))
        return

    challenge = challenge_resp["challenge"].encode("utf-8")
    signature = sign_blob(private_key, challenge)

    verify_resp = send_request(
        {
            "action": "login_verify",
            "username": username,
            "signature": b64e(signature),
        }
    )

    if verify_resp.get("status") != "ok":
        print(verify_resp.get("message", "Login verification failed"))
        return

    CURRENT_USER = username
    CURRENT_PRIVATE_KEY = private_key
    CURRENT_SESSION_TOKEN = verify_resp["session_token"]
    print("Login successful.")


def logout():
    global CURRENT_USER, CURRENT_PRIVATE_KEY, CURRENT_SESSION_TOKEN

    if CURRENT_SESSION_TOKEN:
        send_request(
            {
                "action": "logout",
                "session_token": CURRENT_SESSION_TOKEN,
            }
        )

    CURRENT_USER = None
    CURRENT_PRIVATE_KEY = None
    CURRENT_SESSION_TOKEN = None
    print("Logged out.")


# ==================================================
# CRYPTO HELPERS FOR FILE CONTENT
# ==================================================

def decrypt_file_from_download(download_response: dict):
    meta = download_response["meta"]

    ciphertext = b64d(download_response["ciphertext"])
    nonce = b64d(meta["nonce"])
    tag = b64d(meta["tag"])
    signature = b64d(meta["signature"])

    signer = meta.get("last_modified_by", meta["owner"])
    key_response = send_request(
        {
            "action": "get_public_keys",
            "usernames": [signer],
        }
    )

    if signer not in key_response.get("keys", {}):
        raise Exception("Signer public key not found")

    signer_public = RSA.import_key(key_response["keys"][signer])
    payload = ciphertext + nonce + tag

    if not verify_blob(signer_public, payload, signature):
        raise Exception("Signature invalid")

    wrapped_key = b64d(meta["acl"][CURRENT_USER])
    file_key = PKCS1_OAEP.new(CURRENT_PRIVATE_KEY, hashAlgo=SHA256).decrypt(wrapped_key)

    aes = AES.new(file_key, AES.MODE_GCM, nonce=nonce)
    plaintext = aes.decrypt_and_verify(ciphertext, tag)

    return plaintext, file_key, meta


def encrypt_with_key(plaintext: bytes, file_key: bytes):
    aes = AES.new(file_key, AES.MODE_GCM)
    ciphertext, tag = aes.encrypt_and_digest(plaintext)
    return ciphertext, aes.nonce, tag


# ==================================================
# UPLOAD
# ==================================================

def upload():
    if not CURRENT_USER:
        print("Login first.")
        return

    path_input = input("File path: ").strip()
    file_path = Path(path_input)

    if not file_path.exists():
        print("File not found.")
        return

    acl_input = input("Grant access to (comma-separated): ").strip()
    recipients = {user.strip() for user in acl_input.split(",") if user.strip()}
    recipients.add(CURRENT_USER)

    key_response = send_request(
        {
            "action": "get_public_keys",
            "usernames": sorted(recipients),
        }
    )

    if key_response.get("missing"):
        print("Unknown users:", key_response["missing"])
        return

    plaintext = file_path.read_bytes()
    file_key = get_random_bytes(32)

    ciphertext, nonce, tag = encrypt_with_key(plaintext, file_key)

    acl = {}
    for user, public_pem in key_response["keys"].items():
        public_key = RSA.import_key(public_pem)
        wrapped_key = PKCS1_OAEP.new(public_key, hashAlgo=SHA256).encrypt(file_key)
        acl[user] = b64e(wrapped_key)

    signature = sign_blob(CURRENT_PRIVATE_KEY, ciphertext + nonce + tag)

    response = send_request(
        with_session(
            {
                "action": "upload",
                "filename": file_path.name,
                "ciphertext": b64e(ciphertext),
                "nonce": b64e(nonce),
                "tag": b64e(tag),
                "signature": b64e(signature),
                "acl": acl,
            }
        )
    )

    print(response.get("message", "Upload complete"))


# ==================================================
# LIST + DOWNLOAD
# ==================================================

def list_accessible_files():
    response = send_request(with_session({"action": "list"}))
    if response.get("status") != "ok":
        print(response.get("message", "Unable to list files"))
        return {}

    files = response.get("files", {})
    if not files:
        print("No accessible files.")
        return {}

    for file_id, meta in files.items():
        print(
            f"{file_id} -> {meta['filename']} "
            f"(Owner: {meta['owner']}, Last Modified: {meta['last_modified_by']})"
        )

    return files


def download():
    if not CURRENT_USER:
        print("Login first.")
        return

    files = list_accessible_files()
    if not files:
        return

    file_id = input("File ID: ").strip()

    download_response = send_request(
        with_session(
            {
                "action": "download",
                "file_id": file_id,
            }
        )
    )

    if download_response.get("status") != "ok":
        print(download_response.get("message", "Download failed"))
        return

    try:
        plaintext, _, meta = decrypt_file_from_download(download_response)
    except Exception as exc:
        print("Download failed:", exc)
        return

    output_path = user_dir(CURRENT_USER) / meta["filename"]
    output_path.write_bytes(plaintext)
    print("File saved to:", output_path)


# ==================================================
# MODIFY FILE CONTENT (ACL USER)
# ==================================================

def modify_file():
    if not CURRENT_USER:
        print("Login first.")
        return

    files = list_accessible_files()
    if not files:
        return

    file_id = input("File ID to modify (0 to cancel): ").strip()
    if file_id == "0":
        return

    download_response = send_request(
        with_session(
            {
                "action": "download",
                "file_id": file_id,
            }
        )
    )

    if download_response.get("status") != "ok":
        print(download_response.get("message", "Unable to fetch file"))
        return

    try:
        _, file_key, meta = decrypt_file_from_download(download_response)
    except Exception as exc:
        print("Cannot modify file:", exc)
        return

    edited_path_input = input("Path to edited plaintext file: ").strip()
    edited_path = Path(edited_path_input)

    if not edited_path.exists():
        print("Edited file not found.")
        return

    new_plaintext = edited_path.read_bytes()
    new_ciphertext, new_nonce, new_tag = encrypt_with_key(new_plaintext, file_key)
    new_signature = sign_blob(CURRENT_PRIVATE_KEY, new_ciphertext + new_nonce + new_tag)

    response = send_request(
        with_session(
            {
                "action": "update_file",
                "file_id": file_id,
                "ciphertext": b64e(new_ciphertext),
                "nonce": b64e(new_nonce),
                "tag": b64e(new_tag),
                "signature": b64e(new_signature),
            }
        )
    )

    print(response.get("message", "File updated"))


# ==================================================
# UPDATE ACL (OWNER, WITH RE-KEY)
# ==================================================

def update_acl():
    if not CURRENT_USER:
        print("Login first.")
        return

    files = list_accessible_files()
    owned = {file_id: meta for file_id, meta in files.items() if meta["owner"] == CURRENT_USER}

    if not owned:
        print("You do not own any files.")
        return

    print("\nFiles You Own:")
    for file_id, meta in owned.items():
        print(f"{file_id} -> {meta['filename']}")

    file_id = input("\nFile ID to modify ACL (0 to cancel): ").strip()
    if file_id == "0":
        return

    if file_id not in owned:
        print("Invalid File ID.")
        return

    download_response = send_request(
        with_session(
            {
                "action": "download",
                "file_id": file_id,
            }
        )
    )

    if download_response.get("status") != "ok":
        print(download_response.get("message", "Unable to fetch file"))
        return

    meta = download_response["meta"]
    current_acl = set(meta["acl"].keys())

    print("\nCurrent ACL:", ", ".join(sorted(current_acl)))

    new_acl_input = input("New ACL (comma-separated): ").strip()
    recipients = {user.strip() for user in new_acl_input.split(",") if user.strip()}
    recipients.add(CURRENT_USER)

    key_response = send_request(
        {
            "action": "get_public_keys",
            "usernames": sorted(recipients),
        }
    )

    if key_response.get("missing"):
        print("Unknown users:", key_response["missing"])
        return

    try:
        plaintext, _, _ = decrypt_file_from_download(download_response)
    except Exception as exc:
        print("Cannot update ACL:", exc)
        return

    new_file_key = get_random_bytes(32)
    new_ciphertext, new_nonce, new_tag = encrypt_with_key(plaintext, new_file_key)

    new_acl = {}
    for user, public_pem in key_response["keys"].items():
        public_key = RSA.import_key(public_pem)
        wrapped_key = PKCS1_OAEP.new(public_key, hashAlgo=SHA256).encrypt(new_file_key)
        new_acl[user] = b64e(wrapped_key)

    new_signature = sign_blob(CURRENT_PRIVATE_KEY, new_ciphertext + new_nonce + new_tag)

    response = send_request(
        with_session(
            {
                "action": "update_acl",
                "file_id": file_id,
                "ciphertext": b64e(new_ciphertext),
                "nonce": b64e(new_nonce),
                "tag": b64e(new_tag),
                "signature": b64e(new_signature),
                "acl": new_acl,
            }
        )
    )

    print(response.get("message", "ACL updated"))


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
            print("3 Modify File")
            print("4 Update ACL")
            print("5 Logout")
            print("0 Exit")

            choice = input("Select: ").strip()

            if choice == "1":
                upload()
            elif choice == "2":
                download()
            elif choice == "3":
                modify_file()
            elif choice == "4":
                update_acl()
            elif choice == "5":
                logout()
            elif choice == "0":
                break
            else:
                print("Invalid option.")


if __name__ == "__main__":
    main()
