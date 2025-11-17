#!/usr/bin/env python3
"""
gen_cert.py
Generate a key, CSR and a certificate for either server or client signed by the root CA.

Usage:
  python scripts/gen_cert.py server securechat-server
  python scripts/gen_cert.py client securechat-client

Outputs (into certs/):
  - <role>_key.pem
  - <role>_csr.pem
  - <role>_cert.pem  (signed by rootCA)
"""
import os
import sys
import subprocess

if len(sys.argv) < 3:
    print("Usage: python scripts/gen_cert.py <server|client> <common_name>")
    sys.exit(1)

role = sys.argv[1].lower()
cn = sys.argv[2]

CERT_DIR = "certs"
os.makedirs(CERT_DIR, exist_ok=True)

KEY_PATH = os.path.join(CERT_DIR, f"{role}_key.pem")
CSR_PATH = os.path.join(CERT_DIR, f"{role}_csr.pem")
CRT_PATH = os.path.join(CERT_DIR, f"{role}_cert.pem")
ROOT_KEY = os.path.join(CERT_DIR, "rootCA_key.pem")
ROOT_CRT = os.path.join(CERT_DIR, "rootCA.pem")

if not os.path.exists(ROOT_KEY) or not os.path.exists(ROOT_CRT):
    print("Root CA not found. Run scripts/gen_ca.py first.")
    sys.exit(1)

SUBJ = f"/C=PK/ST=Islamabad/L=Islamabad/O=SecureChat/OU=Security/CN={cn}/emailAddress=you@example.com"

print(f"Generating key for {role}...")
subprocess.check_call(["openssl", "genrsa", "-out", KEY_PATH, "2048"])

print(f"Generating CSR for {role} (CN={cn})...")
subprocess.check_call(["openssl", "req", "-new", "-key", KEY_PATH, "-out", CSR_PATH, "-subj", SUBJ])

print(f"Signing CSR with root CA to create certificate for {role}...")
subprocess.check_call([
    "openssl", "x509", "-req",
    "-in", CSR_PATH,
    "-CA", ROOT_CRT, "-CAkey", ROOT_KEY, "-CAcreateserial",
    "-out", CRT_PATH,
    "-days", "365", "-sha256"
])

print(f"Created {CRT_PATH}")
print("Note: KEEP *_key.pem files private. Do NOT commit them to git.")
