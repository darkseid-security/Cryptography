from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
from colorama import Fore
import sys
import argparse

print("__" * 45)

print(Fore.RED + """
┳┓┏┓┏┓  ┓┏┓┏┓┓┏┏┓┏┓┳┓
┣┫┗┓┣┫  ┃┫ ┣ ┗┫┃┓┣ ┃┃
┛┗┗┛┛┗  ┛┗┛┗┛┗┛┗┛┗┛┛┗ """ + Fore.WHITE + "Generate RSA Keys V1.0 Developed by" + " \033[38;5;208mThe Intrusion Team\033[0m" + Fore.RESET)


print("__" * 45 + "\n")

parser = argparse.ArgumentParser("Help options --keylength")
parser.add_argument("--keylength",type=str, help="Specify keylength for encryption")
args = parser.parse_args()

if args.keylength is None:
    print("[!] Specify keylength: --keylength 4096")
    sys.exit()

print(Fore.BLUE + "[*]" + Fore.WHITE + f" Key Size: {args.keylength} Bits" + Fore.RESET)
print(Fore.BLUE + "[*]" + Fore.WHITE + " Generating public/private key pairs" + Fore.RESET)

def generate_rsa_key_pair():
    print(Fore.BLUE + "[*]" + Fore.WHITE + " Generating RSA public and private key pairs" + Fore.RESET)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=int(args.keylength),
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key
    

def save_key_to_file(filename, key):
    with open(filename, "wb") as key_file:
        key_file.write(key)

# Generate RSA key pair
private_key, public_key = generate_rsa_key_pair()

# Save keys to files
save_key_to_file("private_key.pem", private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
))
save_key_to_file("public_key.pem", public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
))