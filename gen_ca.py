from OpenSSL import crypto
import os

CA_KEY_FILE = "certs/rootCA_key.pem"
CA_CERT_FILE = "certs/rootCA.pem"

def generate_ca():
    if not os.path.exists("certs"):
        os.makedirs("certs")

    # Create key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # Create self-signed certificate
    cert = crypto.X509()
    cert.get_subject().CN = "securechat-CA"
    cert.get_subject().O = "SecureChat"
    cert.get_subject().OU = "Security"
    cert.get_subject().L = "Islamabad"
    cert.get_subject().ST = "Islamabad"
    cert.get_subject().C = "PK"
    cert.get_subject().emailAddress = "toobadahar@gmail.com"

    cert.set_serial_number(1001)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # 1 year validity

    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")

    # Write files
    with open(CA_KEY_FILE, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    with open(CA_CERT_FILE, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    print("Root CA generated successfully!")

if __name__ == "__main__":
    generate_ca()
