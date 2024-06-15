from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Cryptodome.Random import get_random_bytes
import base64
from colorama import Fore
import argparse
import sys

print("__" * 45)

print(Fore.RED + """
╦═╗╔═╗╔═╗  ╔═╗╔╗╔╔═╗╦═╗╦ ╦╔═╗╔╦╗╔═╗╦═╗
╠╦╝╚═╗╠═╣  ║╣ ║║║║  ╠╦╝╚╦╝╠═╝ ║ ║ ║╠╦╝
╩╚═╚═╝╩ ╩  ╚═╝╝╚╝╚═╝╩╚═ ╩ ╩   ╩ ╚═╝╩╚═ """ + Fore.WHITE + "Encrypt RSA Messages V1 Developed By " + "\033[38;5;208mThe Intrusion Team\033[0m" + Fore.RESET)

print("__" * 45 + "\n")

parser = argparse.ArgumentParser("Help options --plaintext")
parser.add_argument("--plaintext",type=str, help="Enter plain text message to encrypt")
args = parser.parse_args()

if args.plaintext is None:
    print("[!] Specify keylength: --plaintext MESSAGE")
    sys.exit()

def load_public_key_from_file(filename):
    try:
        with open(filename, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
            )
        return public_key
    except Exception as e:
        print(f"[!] {str(e)}")

# Load public key from file
loaded_public_key = load_public_key_from_file("public_key.pem")

# Text to be encrypted
plaintext = bytes(args.plaintext,encoding="utf-8")

# Encrypt the plain text using the loaded public key
print(Fore.BLUE + "[*] " + Fore.WHITE + "Plaintext Message:" + Fore.WHITE ,plaintext.decode() , Fore.RESET)
ciphertext = loaded_public_key.encrypt(
    plaintext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# print key size of RSA key
enc_ciphertext = base64.b64encode(ciphertext).decode()

if len(enc_ciphertext) == 172:
    print(Fore.BLUE + "[*] " + Fore.WHITE + "Key Length: 1024 Bits" + Fore.RESET)
if len(enc_ciphertext) == 344:
    print(Fore.BLUE + "[*] " + Fore.WHITE + "Key Length: 2048 Bits" + Fore.RESET)
if len(enc_ciphertext) == 512:
    print(Fore.BLUE + "[*]" + Fore.WHITE + "Key Length: 3072 Bits" + Fore.RESET)
if len(enc_ciphertext) == 684:
    print(Fore.BLUE +  "[*] " + Fore.WHITE + "Key Length: 4096 Bits" + Fore.RESET)
if len(enc_ciphertext) == 1368:
    print(Fore.BLUE + "[*] " + Fore.WHITE + "Key Length: 8192 Bits" + Fore.RESET)
if len(enc_ciphertext) == 2732:
    print(Fore.BLUE + "[*] " + Fore.WHITE + "Key Length: 16384 Bits" + Fore.RESET)
        
print(Fore.BLUE + "[*] " + Fore.WHITE + "Ciphertext:",base64.b64encode(ciphertext).decode())


