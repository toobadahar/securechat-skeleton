"# securechat-skeleton" 
🔐 SecureChat – Encrypted Messaging System

SecureChat is a Python client–server application implementing end-to-end encrypted communication without TLS/SSL.
All encryption, certificate validation, signatures, and key exchange are done at the application layer, as required by the assignment.

🚀 Features

PKI System

Local Root CA

Server & Client certificates

Hostname + expiry checks

Rejects invalid/self-signed certs

Secure Login

Random salt (16B+)

SHA256(salt || password)

No plaintext passwords stored or logged

MySQL backend

Key Exchange & Encryption

Diffie–Hellman shared secret

AES-128 CBC with PKCS#7 padding

Fresh IV per message

Integrity & Authenticity

SHA256(seqno || ts || ciphertext)

RSA signature per message

Replay protection (strict sequence numbers)

Non-Repudiation

Append-only transcript

Server-signed Session Receipt

📁 Project Structure
certs/
client.py
server.py
cert_utils.py
gen_ca.py
gen_cert.py
test_mysql.py
transcripts/
README.md

▶️ How to Run
1) Generate CA & Certificates
python gen_ca.py
python gen_cert.py server
python gen_cert.py client

2) Start Server
python server.py

3) Start Client
python client.py

🧪 PCAP Capture (Wireshark or Terminal)
tcpdump -i any -w securechat.pcap
# or
tshark -i any -w securechat.pcap


Filter encrypted traffic:

tcp.port == 5000

🛠 Technologies Used

Python 3

PyCryptodome (AES, RSA, DH, SHA256)

OpenSSL

MySQL

Wireshark

📌 Summary

SecureChat demonstrates full CIANR:

✔ Confidentiality (AES)
✔ Integrity (SHA256)
✔ Authenticity (RSA signatures)
✔ Non-Repudiation (signed receipt)
✔ Replay Defense (seqno)

A complete, minimal, and secure Python messaging system.