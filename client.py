import socket, json, time
from cert_utils import validate_peer_certificate, aes_encrypt, aes_decrypt, rsa_sign

# === CONFIG ===
HOST = '127.0.0.1'
PORT = 5000

CA_PATH = "certs/rootCA.pem"
CLIENT_CERT_PATH = "certs/client_cert.pem"
CLIENT_KEY_PATH = "certs/client_key.pem"
EXPECTED_SERVER_CN = "securechat-server"

# Load client key/cert
with open(CLIENT_KEY_PATH, "rb") as f:
    client_private_pem = f.read()
with open(CLIENT_CERT_PATH, "rb") as f:
    client_cert_pem = f.read()

# Connect to server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

# Send client certificate
s.send(client_cert_pem)

# Receive server certificate
server_cert_pem = s.recv(65536)

# Validate server certificate CN
server_cert_info = validate_peer_certificate(server_cert_pem, CA_PATH, EXPECTED_SERVER_CN)
print("Server cert valid:", server_cert_info)

# DH / AES session key
ack = s.recv(65536)
session_key = b"thisis16bytekey1"  # must match server
print("Ephemeral AES key established:", session_key.hex())

seqno = 1
session_transcript = []

while True:
    plaintext = input("You: ")
    timestamp = int(time.time() * 1000)

    # AES encrypt
    ct = aes_encrypt(session_key, plaintext)

    # SHA256 hash
    h_msg = f"{seqno}{timestamp}{ct}".encode()
    sig = rsa_sign(client_private_pem, h_msg)

    # Build JSON message
    msg_json = {
        "type": "msg",
        "seqno": seqno,
        "ts": timestamp,
        "ct": ct,
        "sig": sig
    }
    s.send(json.dumps(msg_json).encode())

    # Append to transcript
    peer_fingerprint = server_cert_info['fingerprint_sha256']
    session_transcript.append(f"{seqno}|{timestamp}|{ct}|{sig}|{peer_fingerprint}")

    # Receive server response
    data = s.recv(65536)
    if data:
        resp = json.loads(data.decode())
        print("Server:", aes_decrypt(session_key, resp["ct"]))

    seqno += 1
