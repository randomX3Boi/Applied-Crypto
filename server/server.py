"""
SERVER APPLICATION

Security-focused responsibilities:
1. Store encrypted file blobs only
2. Maintain encrypted metadata (users/files)
3. Enforce ACL and ownership rules
4. Authenticate users via challenge-response signatures
5. Verify signatures for all file write operations
6. Never decrypt user file contents
"""

import base64
import json
import os
import secrets
import time
import uuid
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss


# ==================================================
# PATH CONFIGURATION
# ==================================================

BASE_DIR = Path(__file__).parent.resolve()
STORAGE_DIR = BASE_DIR / "storage"
REQUESTS_DIR = BASE_DIR / "requests"
RESPONSES_DIR = BASE_DIR / "responses"
USERS_FILE = BASE_DIR / "users.json"
FILES_FILE = BASE_DIR / "files.json"
SECRET_FILE = BASE_DIR / "server_secret.key"

for directory in (STORAGE_DIR, REQUESTS_DIR, RESPONSES_DIR):
    directory.mkdir(parents=True, exist_ok=True)


# ==================================================
# SERVER SECRET FOR METADATA PROTECTION
# ==================================================

LEGACY_RAW_SECRET = b"HMAC_SecR3t_WeSh0ulntHardC0D3Th151NH3r3"
LEGACY_SERVER_KEY = SHA256.new(LEGACY_RAW_SECRET).digest()


def load_server_key() -> bytes:
    env_secret = os.environ.get("APP_CRYPTO_SERVER_SECRET")
    if env_secret:
        return SHA256.new(env_secret.encode("utf-8")).digest()

    if SECRET_FILE.exists():
        secret_material = SECRET_FILE.read_bytes()
        return SHA256.new(secret_material).digest()

    random_secret = secrets.token_bytes(32)
    SECRET_FILE.write_bytes(random_secret)
    return SHA256.new(random_secret).digest()


SERVER_KEY = load_server_key()


# ==================================================
# SESSION STATE (IN-MEMORY)
# ==================================================

SESSION_TTL_SECONDS = 3600
CHALLENGE_TTL_SECONDS = 120

active_sessions = {}
pending_challenges = {}


# ==================================================
# METADATA ENCRYPTION + INTEGRITY
# ==================================================

def save_json_secure(path: Path, data: dict):
    plaintext = json.dumps(data, indent=2).encode("utf-8")

    cipher = AES.new(SERVER_KEY, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    blob = cipher.nonce + tag + ciphertext
    path.write_bytes(blob)

    hmac_obj = HMAC.new(SERVER_KEY, blob, digestmod=SHA256)
    hmac_path = path.with_suffix(path.suffix + ".hmac")
    hmac_path.write_text(hmac_obj.hexdigest(), encoding="utf-8")


def decrypt_blob(blob: bytes, key: bytes) -> dict:
    nonce = blob[:16]
    tag = blob[16:32]
    ciphertext = blob[32:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return json.loads(plaintext.decode("utf-8"))


def load_json_secure(path: Path):
    if not path.exists():
        return {}

    blob = path.read_bytes()
    hmac_path = path.with_suffix(path.suffix + ".hmac")

    if not hmac_path.exists():
        raise Exception("HMAC file missing.")

    stored_hmac = hmac_path.read_text(encoding="utf-8")

    keys_to_try = [SERVER_KEY]
    if SERVER_KEY != LEGACY_SERVER_KEY:
        keys_to_try.append(LEGACY_SERVER_KEY)

    verified_key = None
    for key in keys_to_try:
        hmac_obj = HMAC.new(key, blob, digestmod=SHA256)
        if hmac_obj.hexdigest() == stored_hmac:
            verified_key = key
            break

    if verified_key is None:
        raise Exception("Metadata integrity verification FAILED.")

    return decrypt_blob(blob, verified_key)


# ==================================================
# AUTH + SIGNATURE HELPERS
# ==================================================

def verify_signature(public_pem: str, payload: bytes, signature_b64: str) -> bool:
    public_key = RSA.import_key(public_pem)
    signature = base64.b64decode(signature_b64)
    digest = SHA256.new(payload)

    try:
        pss.new(public_key).verify(digest, signature)
        return True
    except (ValueError, TypeError):
        return False


def new_session(username: str) -> str:
    token = str(uuid.uuid4())
    active_sessions[token] = {
        "username": username,
        "expires_at": time.time() + SESSION_TTL_SECONDS,
    }
    return token


def cleanup_expired_auth_state():
    now = time.time()

    expired_sessions = [
        token for token, data in active_sessions.items()
        if data["expires_at"] < now
    ]
    for token in expired_sessions:
        active_sessions.pop(token, None)

    expired_challenges = [
        username for username, data in pending_challenges.items()
        if data["expires_at"] < now
    ]
    for username in expired_challenges:
        pending_challenges.pop(username, None)


def require_session(request: dict):
    token = request.get("session_token")
    if not token:
        return None, {"status": "error", "message": "Missing session token"}

    session_data = active_sessions.get(token)
    if not session_data:
        return None, {"status": "error", "message": "Invalid session"}

    if session_data["expires_at"] < time.time():
        active_sessions.pop(token, None)
        return None, {"status": "error", "message": "Session expired"}

    return session_data["username"], None


# ==================================================
# FILE HELPERS
# ==================================================

def next_file_id(files: dict) -> str:
    if not files:
        return "1"
    numeric_ids = [int(file_id) for file_id in files.keys()]
    return str(max(numeric_ids) + 1)


def signed_payload(ciphertext_b64: str, nonce_b64: str, tag_b64: str) -> bytes:
    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    tag = base64.b64decode(tag_b64)
    return ciphertext + nonce + tag


def resolve_cipher_path(file_id: str, meta: dict) -> Path:
    stored_path = Path(meta["cipher_path"])
    if stored_path.exists():
        return stored_path

    candidates = [
        STORAGE_DIR / stored_path.name,
        STORAGE_DIR / f"file_{file_id}.bin",
    ]

    for candidate in candidates:
        if candidate.exists():
            meta["cipher_path"] = str(candidate)
            return candidate

    raise FileNotFoundError(f"Ciphertext blob missing for file_id={file_id}")


print("Server running.")


# ==================================================
# MAIN REQUEST LOOP
# ==================================================

while True:
    cleanup_expired_auth_state()

    for req_file in REQUESTS_DIR.glob("*.json"):
        request = json.loads(req_file.read_text(encoding="utf-8"))
        action = request.get("action")
        response = {}

        try:
            users = load_json_secure(USERS_FILE)
            files = load_json_secure(FILES_FILE)
        except Exception as exc:
            print(exc)
            raise SystemExit("Server stopped due to metadata tampering.")

        if action == "register":
            username = request["username"]
            public_key = request["public_key"]

            if username in users:
                response = {"status": "error", "message": "User exists"}
            else:
                users[username] = {"public_key": public_key}
                save_json_secure(USERS_FILE, users)
                response = {"status": "ok"}

        elif action == "login_challenge":
            username = request.get("username", "")
            if username not in users:
                response = {"status": "error", "message": "Unknown user"}
            else:
                challenge = secrets.token_urlsafe(32)
                pending_challenges[username] = {
                    "challenge": challenge,
                    "expires_at": time.time() + CHALLENGE_TTL_SECONDS,
                }
                response = {"status": "ok", "challenge": challenge}

        elif action == "login_verify":
            username = request.get("username", "")
            signature_b64 = request.get("signature", "")
            challenge_data = pending_challenges.get(username)

            if username not in users or not challenge_data:
                response = {"status": "error", "message": "No active challenge"}
            elif challenge_data["expires_at"] < time.time():
                pending_challenges.pop(username, None)
                response = {"status": "error", "message": "Challenge expired"}
            else:
                challenge = challenge_data["challenge"].encode("utf-8")
                public_pem = users[username]["public_key"]

                if not verify_signature(public_pem, challenge, signature_b64):
                    response = {"status": "error", "message": "Invalid login signature"}
                else:
                    pending_challenges.pop(username, None)
                    token = new_session(username)
                    response = {
                        "status": "ok",
                        "session_token": token,
                        "expires_in": SESSION_TTL_SECONDS,
                    }

        elif action == "logout":
            token = request.get("session_token")
            if token and token in active_sessions:
                active_sessions.pop(token, None)
            response = {"status": "ok", "message": "Logged out"}

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

        elif action == "upload":
            username, error = require_session(request)
            if error:
                response = error
            else:
                payload = signed_payload(
                    request["ciphertext"],
                    request["nonce"],
                    request["tag"],
                )
                public_pem = users[username]["public_key"]

                if not verify_signature(public_pem, payload, request["signature"]):
                    response = {"status": "error", "message": "Invalid upload signature"}
                else:
                    acl = request["acl"]
                    if username not in acl:
                        response = {"status": "error", "message": "Owner must be in ACL"}
                    else:
                        file_id = next_file_id(files)
                        cipher_path = STORAGE_DIR / f"file_{file_id}.bin"
                        cipher_path.write_bytes(base64.b64decode(request["ciphertext"]))

                        files[file_id] = {
                            "owner": username,
                            "filename": request["filename"],
                            "cipher_path": str(cipher_path),
                            "nonce": request["nonce"],
                            "tag": request["tag"],
                            "signature": request["signature"],
                            "last_modified_by": username,
                            "acl": acl,
                        }

                        save_json_secure(FILES_FILE, files)
                        response = {"status": "ok", "file_id": file_id, "message": "Uploaded"}

        elif action == "list":
            username, error = require_session(request)
            if error:
                response = error
            else:
                accessible = {}
                for file_id, meta in files.items():
                    if username in meta.get("acl", {}):
                        accessible[file_id] = {
                            "filename": meta["filename"],
                            "owner": meta["owner"],
                            "last_modified_by": meta.get("last_modified_by", meta["owner"]),
                        }
                response = {"status": "ok", "files": accessible}

        elif action == "download":
            username, error = require_session(request)
            file_id = request.get("file_id", "")

            if error:
                response = error
            elif file_id not in files:
                response = {"status": "error", "message": "File not found"}
            else:
                meta = files[file_id]
                if username not in meta.get("acl", {}):
                    response = {"status": "error", "message": "Access denied"}
                else:
                    try:
                        cipher_path = resolve_cipher_path(file_id, meta)
                        ciphertext_b64 = base64.b64encode(
                            cipher_path.read_bytes()
                        ).decode("utf-8")
                        files[file_id] = meta
                        save_json_secure(FILES_FILE, files)
                        response = {
                            "status": "ok",
                            "meta": meta,
                            "ciphertext": ciphertext_b64,
                        }
                    except FileNotFoundError:
                        response = {"status": "error", "message": "Encrypted file missing on server"}

        elif action == "update_file":
            username, error = require_session(request)
            file_id = request.get("file_id", "")

            if error:
                response = error
            elif file_id not in files:
                response = {"status": "error", "message": "File not found"}
            else:
                meta = files[file_id]
                if username not in meta.get("acl", {}):
                    response = {"status": "error", "message": "Access denied"}
                else:
                    payload = signed_payload(
                        request["ciphertext"],
                        request["nonce"],
                        request["tag"],
                    )
                    signer_public_key = users[username]["public_key"]

                    if not verify_signature(signer_public_key, payload, request["signature"]):
                        response = {"status": "error", "message": "Invalid update signature"}
                    else:
                        try:
                            cipher_path = resolve_cipher_path(file_id, meta)
                            cipher_path.write_bytes(base64.b64decode(request["ciphertext"]))
                            meta["cipher_path"] = str(cipher_path)
                            meta["nonce"] = request["nonce"]
                            meta["tag"] = request["tag"]
                            meta["signature"] = request["signature"]
                            meta["last_modified_by"] = username
                            files[file_id] = meta
                            save_json_secure(FILES_FILE, files)
                            response = {"status": "ok", "message": "File updated"}
                        except FileNotFoundError:
                            response = {"status": "error", "message": "Encrypted file missing on server"}

        elif action == "update_acl":
            username, error = require_session(request)
            file_id = request.get("file_id", "")

            if error:
                response = error
            elif file_id not in files:
                response = {"status": "error", "message": "File not found"}
            else:
                meta = files[file_id]

                if username != meta["owner"]:
                    response = {"status": "error", "message": "Only owner can update ACL"}
                else:
                    payload = signed_payload(
                        request["ciphertext"],
                        request["nonce"],
                        request["tag"],
                    )
                    owner_public_key = users[username]["public_key"]

                    if not verify_signature(owner_public_key, payload, request["signature"]):
                        response = {"status": "error", "message": "Invalid signature"}
                    else:
                        new_acl = request["acl"]
                        if username not in new_acl:
                            response = {"status": "error", "message": "Owner must remain in ACL"}
                        else:
                            try:
                                cipher_path = resolve_cipher_path(file_id, meta)
                                cipher_path.write_bytes(base64.b64decode(request["ciphertext"]))
                                meta["cipher_path"] = str(cipher_path)
                                meta["nonce"] = request["nonce"]
                                meta["tag"] = request["tag"]
                                meta["signature"] = request["signature"]
                                meta["last_modified_by"] = username
                                meta["acl"] = new_acl
                                files[file_id] = meta
                                save_json_secure(FILES_FILE, files)
                                response = {"status": "ok", "message": "ACL updated"}
                            except FileNotFoundError:
                                response = {"status": "error", "message": "Encrypted file missing on server"}

        else:
            response = {"status": "error", "message": "Unknown action"}

        (RESPONSES_DIR / req_file.name).write_text(
            json.dumps(response),
            encoding="utf-8",
        )
        req_file.unlink()

    time.sleep(0.2)
