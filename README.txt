Applied Crypto - Secure File Sharing Platform
============================================

Overview
--------
This project implements a client-server platform for secure file sharing with encryption-based access control.

Security goals:
1. Files are encrypted at all times on the server.
2. Only users in a file's ACL can decrypt and modify the file.
3. File owner controls ACL changes.
4. Server never stores private keys or plaintext files.


Architecture
------------
Client responsibilities:
- Generate RSA keypair per user.
- Encrypt private key locally with PBKDF2 + AES-GCM.
- Encrypt files with AES-GCM and wrap file key per ACL user with RSA-OAEP.
- Sign file payloads with RSA-PSS for authenticity.
- Perform owner-only ACL re-key operations.

Server responsibilities:
- Store encrypted file blobs and encrypted metadata.
- Authenticate users using challenge-response signatures.
- Manage session tokens and ACL/ownership metadata.
- Verify signatures on all file write operations.
- Enforce ACL checks for listing, download, and update operations.


Cryptographic design
--------------------
1) Confidentiality
- File content encryption: AES-256-GCM (client side).
- Hybrid access control: per-file AES key wrapped with RSA-OAEP for each ACL member.

2) Integrity and authenticity
- File payload signature: RSA-PSS over (ciphertext || nonce || tag).
- Server verifies signatures before accepting uploads and updates.
- Metadata protection: AES-GCM encryption + HMAC-SHA256 integrity check.

3) Access control and revocation
- ACL stored as {username -> wrapped_file_key}.
- Owner ACL updates perform secure re-keying:
  - Decrypt old file.
  - Generate new AES key.
  - Re-encrypt file and re-wrap for new ACL users only.

4) Authentication
- Login is challenge-response:
  - Server issues random challenge.
  - Client signs challenge with private key.
  - Server verifies with registered public key and returns session token.


Main features
-------------
- Register user with public key upload.
- Login/logout with session token.
- Upload encrypted file with ACL.
- List files accessible to logged-in user.
- Download/decrypt file locally.
- Modify file content (any ACL user).
- Update ACL with owner-only secure re-keying.


How to run
----------
1. Start server:
   - Open terminal in server/
   - Run: python server.py

2. Start client:
   - Open terminal in client/
   - Run: python client.py

3. Use client menu to register/login and perform operations.


Demo checklist (for grading)
----------------------------
1. Register two users (owner + collaborator).
2. Owner uploads a file and grants collaborator access.
3. Collaborator downloads and decrypts file successfully.
4. Collaborator modifies file content and updates encrypted file.
5. Owner removes collaborator from ACL (re-keying).
6. Collaborator can no longer decrypt updated file.


Notes
-----
- Existing sample users in users/ may be reused if their private keys are available.
- Server metadata key can be provided via APP_CRYPTO_SERVER_SECRET environment variable.
- If no environment secret is provided, server generates and stores one in server/server_secret.key.
