import socket, json, time
from cert_utils import validate_peer_certificate, aes_encrypt, aes_decrypt, rsa_sign, rsa_verify

# === CONFIG ===
HOST = '127.0.0.1'
PORT = 5000

CA_PATH = "certs/rootCA.pem"
SERVER_CERT_PATH = "certs/server_cert.pem"
SERVER_KEY_PATH = "certs/server_key.pem"
EXPECTED_CLIENT_CN = "securechat-client"

# Load server key/cert
with open(SERVER_KEY_PATH, "rb") as f:
    server_private_pem = f.read()
with open(SERVER_CERT_PATH, "rb") as f:
    server_cert_pem = f.read()

# Create server socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(1)
print("Server listening...")

conn, addr = s.accept()
print("Connected by", addr)

# Receive client certificate
client_cert_pem = conn.recv(65536)
client_cert_info = validate_peer_certificate(client_cert_pem, CA_PATH, EXPECTED_CLIENT_CN)
print("Client cert valid:", client_cert_info)

# Send server certificate to client
conn.send(server_cert_pem)

# === DH key agreement (simplified example) ===
session_key = b"thisis16bytekey1"  # 16-byte AES key (must be exactly 16 bytes)
conn.send(b"KEY_OK")  # notify client key agreed
print("Ephemeral AES key established:", session_key.hex())

seqno = 1
session_transcript = []

while True:
    data = conn.recv(65536)
    if not data:
        break
    try:
        msg_json = json.loads(data.decode())
    except:
        print("Invalid JSON from client")
        continue

    seq = msg_json.get("seqno")
    ts = msg_json.get("ts")
    ct = msg_json.get("ct")
    sig = msg_json.get("sig")

    # Verify signature
    valid = rsa_verify(client_cert_pem, f"{seq}{ts}{ct}".encode(), sig)
    if not valid:
        print("SIG FAIL for message", seq)
        continue

    # Decrypt
    plaintext = aes_decrypt(session_key, ct)
    print(f"Client: {plaintext}")

    # Append to transcript
    session_transcript.append(f"{seq}|{ts}|{ct}|{sig}|{client_cert_info['fingerprint_sha256']}")

    # Send reply (echo server)
    reply_text = f"Server received: {plaintext}"
    reply_ct = aes_encrypt(session_key, reply_text)
    reply_json = {"type": "msg", "ct": reply_ct}
    conn.send(json.dumps(reply_json).encode())
    seqno += 1

# === Generate SessionReceipt ===
from Crypto.Hash import SHA256
transcript_str = "".join(session_transcript)
transcript_hash = SHA256.new(transcript_str.encode()).hexdigest()
receipt_sig = rsa_sign(server_private_pem, transcript_hash.encode())
session_receipt = {
    "type": "receipt",
    "first_seq": 1,
    "last_seq": seqno - 1,
    "transcript_sha256": transcript_hash,
    "sig": receipt_sig
}
with open("session_receipt.json", "w") as f:
    json.dump(session_receipt, f, indent=2)
print("SessionReceipt saved. Server shutting down.")
conn.close()
s.close()
