# cert_utils.py
import base64
import json
import time
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID, ExtensionOID
from datetime import datetime, timezone
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

class CertValidationError(Exception):
    pass

def load_pem_cert(pem_bytes: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem_bytes)

def compute_cert_sha256_fingerprint(cert: x509.Certificate) -> str:
    der = cert.public_bytes(serialization.Encoding.DER)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return digest.finalize().hex()

def validate_cert_signed_by_ca(cert: x509.Certificate, ca_cert: x509.Certificate):
    pubkey = ca_cert.public_key()
    try:
        pubkey.verify(
            signature=cert.signature,
            data=cert.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=cert.signature_hash_algorithm,
        )
    except Exception as e:
        raise CertValidationError(f"Signature verification failed: {e}")
def validate_cert_dates(cert):
    from datetime import datetime, timezone

    # Convert certificate dates to naive UTC datetime
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after

    if not_before.tzinfo is not None:
        not_before = not_before.astimezone(timezone.utc).replace(tzinfo=None)
    if not_after.tzinfo is not None:
        not_after = not_after.astimezone(timezone.utc).replace(tzinfo=None)

    now = datetime.utcnow()  # naive UTC
    if not_before > now:
        raise CertValidationError(f"Certificate not yet valid: {cert.not_valid_before}")
    if not_after < now:
        raise CertValidationError(f"Certificate expired: {cert.not_valid_after}")

def get_common_name(cert: x509.Certificate) -> str:
    cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return cn_attr[0].value if cn_attr else ""

def validate_peer_certificate(peer_pem: bytes, ca_pem_path: str, expected_cn: str):
    peer_cert = load_pem_cert(peer_pem)
    with open(ca_pem_path, "rb") as f:
        ca_cert = load_pem_cert(f.read())
    validate_cert_signed_by_ca(peer_cert, ca_cert)
    validate_cert_dates(peer_cert)
    cn = get_common_name(peer_cert)
    if cn != expected_cn:
        raise CertValidationError(f"CN mismatch: expected={expected_cn}, got={cn}")
    return {
        "subject_cn": cn,
        "not_valid_before": peer_cert.not_valid_before,
        "not_valid_after": peer_cert.not_valid_after,
        "fingerprint_sha256": compute_cert_sha256_fingerprint(peer_cert),
        "issuer": peer_cert.issuer.rfc4514_string()
    }

# AES encrypt/decrypt
def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(ct_bytes).decode()

def aes_decrypt(key, ciphertext_b64):
    cipher = AES.new(key, AES.MODE_ECB)
    ct_bytes = base64.b64decode(ciphertext_b64)
    return unpad(cipher.decrypt(ct_bytes), AES.block_size).decode()

# RSA sign and verify
def rsa_sign(private_key_pem, message):
    key = RSA.import_key(private_key_pem)
    h = SHA256.new(message)
    signature = pkcs1_15.new(key).sign(h)
    return base64.b64encode(signature).decode()

def rsa_verify(public_key_pem, message, signature_b64):
    key = RSA.import_key(public_key_pem)
    h = SHA256.new(message)
    signature = base64.b64decode(signature_b64)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
