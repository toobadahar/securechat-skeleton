#!/usr/bin/env python3
"""
gen_ca.py
Generate a simple root CA (private key + self-signed cert) into certs/ folder.

Usage:
  python scripts/gen_ca.py

Outputs (into certs/):
  - rootCA_key.pem   (PRIVATE: do NOT commit)
  - rootCA.pem       (public CA certificate)
  - rootCA.srl       (serial file OpenSSL creates)
"""
import os
import subprocess

CERT_DIR = "certs"
os.makedirs(CERT_DIR, exist_ok=True)

# Adjust subject fields as you like (CN should identify your root CA)
SUBJ = "/C=PK/ST=Islamabad/L=Islamabad/O=SecureChat/OU=Security/CN=securechat-rootCA/emailAddress=you@example.com"

KEY_PATH = os.path.join(CERT_DIR, "rootCA_key.pem")
CRT_PATH = os.path.join(CERT_DIR, "rootCA.pem")

print("Generating Root CA key...")
subprocess.check_call(["openssl", "genrsa", "-out", KEY_PATH, "2048"])

print("Generating self-signed Root CA certificate...")
subprocess.check_call([
    "openssl", "req", "-x509", "-new", "-nodes",
    "-key", KEY_PATH,
    "-sha256", "-days", "3650",
    "-out", CRT_PATH,
    "-subj", SUBJ
])

print(f"Root CA created:\n  key: {KEY_PATH}\n  cert: {CRT_PATH}")
print("IMPORTANT: Keep rootCA_key.pem private. Add certs/*_key.pem to .gitignore.")
