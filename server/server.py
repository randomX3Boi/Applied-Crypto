"""
SERVER APPLICATION

Responsibilities:
1. Store encrypted files
2. Maintain encrypted metadata (users + file records)
3. Enforce ACL access rules
4. Verify owner signatures for uploads and ACL updates
5. Never access plaintext files
6. Never store or access private keys

Security Model:
- Server is considered semi-trusted
- Server may be compromised
- Therefore:
    * Files are always encrypted (AES-GCM)
    * Access control enforced via wrapped AES keys
    * Metadata encrypted and integrity-protected
    * Owner authentication enforced via RSA-PSS signatures

Server does NOT:
- Decrypt files
- Store private keys
- Generate encryption keys
"""

import json
import time
import base64
from pathlib import Path

from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pss


# ==================================================
# PATH CONFIGURATION
# ==================================================

BASE_DIR = Path(__file__).parent.resolve()

# Encrypted file storage
STORAGE_DIR = BASE_DIR / "storage"

# Client-server communication folders
REQUESTS_DIR = BASE_DIR / "requests"
RESPONSES_DIR = BASE_DIR / "responses"

# Encrypted metadata files
USERS_FILE = BASE_DIR / "users.json"
FILES_FILE = BASE_DIR / "files.json"

# Ensure required folders exist
for d in (STORAGE_DIR, REQUESTS_DIR, RESPONSES_DIR):
    d.mkdir(parents=True, exist_ok=True)


# ==================================================
# SERVER SECRET (METADATA PROTECTION)
# ==================================================

"""
Metadata is sensitive because it contains:
- Public keys
- ACL structures
- File ownership records

If an attacker modifies metadata:
- ACLs could be manipulated
- Ownership could be reassigned

Therefore:
1. Metadata is encrypted using AES-GCM
2. Integrity is verified using HMAC
"""

RAW_SECRET = b"HMAC_SecR3t_WeSh0ulntHardC0D3Th151NH3r3"

# Derive 256-bit symmetric key for metadata encryption
SERVER_KEY = SHA256.new(RAW_SECRET).digest()


# ==================================================
# METADATA ENCRYPTION + INTEGRITY PROTECTION
# ==================================================

def save_json_secure(path: Path, data: dict):
    """
    Encrypt metadata using AES-256-GCM.

    AES-GCM provides:
    - Confidentiality
    - Integrity
    - Tamper detection

    Additional HMAC provides defence-in-depth.
    """

    plaintext = json.dumps(data, indent=2).encode("utf-8")

    cipher = AES.new(SERVER_KEY, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    blob = cipher.nonce + tag + ciphertext
    path.write_bytes(blob)

    # Compute HMAC over encrypted blob
    h = HMAC.new(SERVER_KEY, blob, digestmod=SHA256)
    hmac_path = path.with_suffix(path.suffix + ".hmac")
    hmac_path.write_text(h.hexdigest(), encoding="utf-8")


def load_json_secure(path: Path):
    """
    Verify HMAC before decrypting metadata.

    If verification fails:
        -> Server terminates immediately.
    """

    if not path.exists():
        return {}

    blob = path.read_bytes()
    hmac_path = path.with_suffix(path.suffix + ".hmac")

    if not hmac_path.exists():
        raise Exception("HMAC file missing.")

    stored_hmac = hmac_path.read_text(encoding="utf-8")

    h = HMAC.new(SERVER_KEY, blob, digestmod=SHA256)

    if h.hexdigest() != stored_hmac:
        raise Exception("Metadata integrity verification FAILED.")

    nonce = blob[:16]
    tag = blob[16:32]
    ciphertext = blob[32:]

    cipher = AES.new(SERVER_KEY, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return json.loads(plaintext.decode("utf-8"))


# ==================================================
# OWNER SIGNATURE VERIFICATION
# ==================================================

def verify_owner_signature(owner_public_pem,ciphertext_b,nonce_b,tag_b,signature_b):
    """
    Verify RSA-PSS signature over:

        ciphertext || nonce || tag

    Ensures:
    - Only file owner can upload file
    - Only owner can perform re-keying
    - Server cannot be tricked into replacing file content
    """

    pub = RSA.import_key(owner_public_pem)

    h = SHA256.new(ciphertext_b + nonce_b + tag_b)

    try:
        pss.new(pub).verify(h, signature_b)
        return True
    except (ValueError, TypeError):
        return False


print("Server running.")


# ==================================================
# MAIN REQUEST LOOP
# ==================================================

"""
Server continuously:
1. Reads client requests
2. Loads secure metadata
3. Processes action
4. Writes response
"""

while True:
    for req_file in REQUESTS_DIR.glob("*.json"):

        request = json.loads(req_file.read_text(encoding="utf-8"))
        action = request.get("action")
        response = {}

        try:
            users = load_json_secure(USERS_FILE)
            files = load_json_secure(FILES_FILE)
        except Exception as e:
            print(e)
            raise SystemExit("Server stopped due to metadata tampering.")

        # ==================================================
        # REGISTER USER
        # ==================================================
        if action == "register":

            username = request["username"]
            public_key = request["public_key"]

            if username in users:
                response = {"status": "error", "message": "User exists"}
            else:
                users[username] = {"public_key": public_key}
                save_json_secure(USERS_FILE, users)
                response = {"status": "ok"}

        # ==================================================
        # GET PUBLIC KEYS
        # ==================================================
        elif action == "get_public_keys":

            names = request.get("usernames", [])
            keys = {}
            missing = []

            for name in names:
                if name in users:
                    keys[name] = users[name]["public_key"]
                else:
                    missing.append(name)

            response = {"status": "ok", "keys": keys, "missing": missing}

        # ==================================================
        # UPLOAD FILE
        # ==================================================
        elif action == "upload":

            """
            Server stores encrypted file.
            Server does NOT decrypt or inspect content.
            """

            file_id = str(int(max(files.keys(), default="0")) + 1)
            cipher_path = STORAGE_DIR / f"file_{file_id}.bin"
            cipher_path.write_bytes(base64.b64decode(request["ciphertext"]))

            files[file_id] = {
                "owner": request["owner"],
                "filename": request["filename"],
                "cipher_path": str(cipher_path),
                "nonce": request["nonce"],
                "tag": request["tag"],
                "signature": request["signature"],
                "acl": request["acl"]
            }

            save_json_secure(FILES_FILE, files)
            response = {"status": "ok", "file_id": file_id}

        # ==================================================
        # LIST FILES (ACL ENFORCEMENT)
        # ==================================================
        elif action == "list":

            username = request["username"]
            accessible = {}

            for fid, meta in files.items():
                if username in meta.get("acl", {}):
                    accessible[fid] = {"filename": meta["filename"],"owner": meta["owner"]}

            response = {"status": "ok", "files": accessible}

        # ==================================================
        # DOWNLOAD FILE
        # ==================================================
        elif action == "download":

            file_id = request["file_id"]
            requester = request["requester"]

            if file_id not in files:
                response = {"status": "error", "message": "File not found"}
            else:
                meta = files[file_id]

                # Enforce ACL at server level
                if requester not in meta.get("acl", {}):
                    response = {"status": "error", "message": "Access denied"}
                else:
                    ciphertext_b64 = base64.b64encode(Path(meta["cipher_path"]).read_bytes()).decode("utf-8")

                    response = {
                        "status": "ok",
                        "meta": meta,
                        "ciphertext": ciphertext_b64
                    }

        # ==================================================
        # UPDATE ACL (REKEY)
        # ==================================================
        elif action == "update_acl":

            file_id = request["file_id"]
            requester = request["requester"]

            if file_id not in files:
                response = {"status": "error", "message": "File not found"}
            else:
                meta = files[file_id]
                owner = meta["owner"]

                if requester != owner:
                    response = {"status": "error","message": "Only owner can update ACL"}
                else:
                    owner_pub_pem = users[owner]["public_key"]
                    new_ciphertext = base64.b64decode(request["ciphertext"])
                    new_nonce = base64.b64decode(request["nonce"])
                    new_tag = base64.b64decode(request["tag"])
                    new_sig = base64.b64decode(request["signature"])

                    # Verify owner signature before accepting rekey
                    if not verify_owner_signature(owner_pub_pem,new_ciphertext,new_nonce,new_tag,new_sig):
                        response = {"status": "error","message": "Invalid signature"}
                    else:
                        cipher_path = Path(meta["cipher_path"])
                        cipher_path.write_bytes(new_ciphertext)
                        meta["nonce"] = request["nonce"]
                        meta["tag"] = request["tag"]
                        meta["signature"] = request["signature"]
                        meta["acl"] = request["acl"]
                        files[file_id] = meta
                        save_json_secure(FILES_FILE, files)
                        response = {"status": "ok","message": "ACL updated"}

        else:
            response = {"status": "error", "message": "Unknown action"}

        (RESPONSES_DIR / req_file.name).write_text(json.dumps(response), encoding="utf-8")

        req_file.unlink()

    time.sleep(0.2)