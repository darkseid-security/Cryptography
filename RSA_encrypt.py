from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
from colorama import Fore
import sys

print(Fore.RED + """
┳┓┏┓┏┓  ┏┓┳┓┏┓┳┓┓┏┏┓┏┳┓┏┓┳┓
┣┫┗┓┣┫  ┣ ┃┃┃ ┣┫┗┫┃┃ ┃ ┣ ┣┫
┛┗┗┛┛┗  ┗┛┛┗┗┛┛┗┗┛┣┛ ┻ ┗┛┛┗ """ + Fore.WHITE + "Encrypt Messages with RSA V1.0 Developed by " + Fore.GREEN + "ENVY IT GROUP" + Fore.RESET)

def load_public_key_from_file(filename):
    with open(filename, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

# Load public key from file
try:
    pub_key = "public_key.pem"
    loaded_public_key = load_public_key_from_file(pub_key)
except FileNotFoundError:
    print(f"[!] {pub_key} Not Found")
    sys.exit()
# Text to be encrypted
plaintext = b"This is a secret message."

# Encrypt the plain text using the loaded public key
print("Message: " + Fore.WHITE + plaintext.decode() + Fore.RESET)
ciphertext = loaded_public_key.encrypt(
    plaintext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA512()),
        algorithm=hashes.SHA512(),
        label=None
    )
)

# print key size of RSA key
enc_ciphertext = base64.b64encode(ciphertext).decode()

print("Ciphertext:",base64.b64encode(ciphertext).decode())


