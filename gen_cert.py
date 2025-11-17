from OpenSSL import crypto
import sys
import os

CA_KEY_FILE = "certs/rootCA_key.pem"
CA_CERT_FILE = "certs/rootCA.pem"

def generate_cert(common_name, out_cert, out_key):
    if not os.path.exists(CA_CERT_FILE) or not os.path.exists(CA_KEY_FILE):
        print("CA files missing! Run gen_ca.py first.")
        return

    # Load CA
    with open(CA_CERT_FILE, "rb") as f:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

    with open(CA_KEY_FILE, "rb") as f:
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

    # Key for server/client
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # New certificate
    cert = crypto.X509()
    subj = cert.get_subject()
    subj.CN = common_name
    subj.O = "SecureChat"
    subj.OU = "Security"
    subj.L = "Islamabad"
    subj.ST = "Islamabad"
    subj.C = "PK"

    cert.set_serial_number(os.urandom(16).hex().__hash__() % (2**64))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)

    cert.set_issuer(ca_cert.get_subject())  # signed by CA
    cert.set_pubkey(key)
    cert.sign(ca_key, "sha256")

    # Save files
    with open(out_key, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    with open(out_cert, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    print(f"Certificate created: {out_cert}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python gen_cert.py <CN> <cert_out> <key_out>")
        exit(0)

    generate_cert(sys.argv[1], sys.argv[2], sys.argv[3])
from OpenSSL import crypto
import sys
import os

CA_KEY_FILE = "certs/rootCA_key.pem"
CA_CERT_FILE = "certs/rootCA.pem"

def generate_cert(common_name, out_cert, out_key):
    if not os.path.exists(CA_CERT_FILE) or not os.path.exists(CA_KEY_FILE):
        print("CA files missing! Run gen_ca.py first.")
        return

    # Load CA
    with open(CA_CERT_FILE, "rb") as f:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

    with open(CA_KEY_FILE, "rb") as f:
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

    # Key for server/client
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # New certificate
    cert = crypto.X509()
    subj = cert.get_subject()
    subj.CN = common_name
    subj.O = "SecureChat"
    subj.OU = "Security"
    subj.L = "Islamabad"
    subj.ST = "Islamabad"
    subj.C = "PK"

    cert.set_serial_number(os.urandom(16).hex().__hash__() % (2**64))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)

    cert.set_issuer(ca_cert.get_subject())  # signed by CA
    cert.set_pubkey(key)
    cert.sign(ca_key, "sha256")

    # Save files
    with open(out_key, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    with open(out_cert, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    print(f"Certificate created: {out_cert}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python gen_cert.py <CN> <cert_out> <key_out>")
        exit(0)

    generate_cert(sys.argv[1], sys.argv[2], sys.argv[3])
