from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
from colorama import Fore

# configuration set key sizes
key_length = 4096

print(Fore.RED + """
┳┓┏┓┏┓  ┓┏┓┏┓┓┏┏┓┏┓┳┓
┣┫┗┓┣┫  ┃┫ ┣ ┗┫┃┓┣ ┃┃
┛┗┗┛┛┗  ┛┗┛┗┛┗┛┗┛┗┛┛┗ """ + Fore.WHITE + "Generate RSA Keys V1.0 " + Fore.YELLOW + "Developed by Sovereign Hacking Team" + Fore.RESET)

print(Fore.BLUE + "[*]" + Fore.WHITE + f" Key Size: {key_length} Bits" + Fore.RESET)

def generate_rsa_key_pair():
    print(Fore.BLUE + "[*]" + Fore.WHITE + " Generating RSA public and private key pairs" + Fore.RESET)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_length,
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

