from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
from colorama import Fore
import argparse
import sys


print("__" * 45)

print(Fore.RED + """
╦═╗╔═╗╔═╗  ╔╦╗╔═╗╔═╗╦═╗╦ ╦╔═╗╔╦╗╔═╗╦═╗
╠╦╝╚═╗╠═╣   ║║║╣ ║  ╠╦╝╚╦╝╠═╝ ║ ║ ║╠╦╝
╩╚═╚═╝╩ ╩  ═╩╝╚═╝╚═╝╩╚═ ╩ ╩   ╩ ╚═╝╩╚═ """ + Fore.WHITE + "Decrypt RSA Messages V1 Developed By " + "\033[38;5;208mThe Intrusion Team\033[0m" + Fore.RESET)

print("__" * 45 + "\n")

parser = argparse.ArgumentParser("Help options --encrypted_message")
parser.add_argument("--encrypted_message",type=str, help="Enter ciphertext to decrypt message")
args = parser.parse_args()

if args.encrypted_message is None:
    print("[!] Specify keylength: --encrypted_message CIPHERTEXT")
    sys.exit()


def load_private_key_from_file(filename):
    try:
        with open(filename, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
            )
        return private_key
    except Exception as e:
        print(f"[!] {str(e)}")

# Load private key from file
loaded_private_key = load_private_key_from_file("private_key.pem")

try:
    ciphertext = bytes(args.encrypted_message,encoding="utf-8")
    
    # print key size of RSA key
    if len(ciphertext) == 172:
        print(Fore.BLUE + "[*] " + Fore.WHITE + "Key Length: 1024 Bits" + Fore.RESET)
    if len(ciphertext) == 344:
        print(Fore.BLUE + "[*] " + Fore.WHITE + "Key Length: 2048 Bits" + Fore.RESET)
    if len(ciphertext) == 512:
        print(Fore.BLUE + "[*]" + Fore.WHITE + "Key Length: 3072 Bits" + Fore.RESET)
    if len(ciphertext) == 684:
        print(Fore.BLUE +  "[*] " + Fore.WHITE + "Key Length: 4096 Bits" + Fore.RESET)
    if len(ciphertext) == 1368:
        print(Fore.BLUE + "[*] " + Fore.WHITE + "Key Length: 8192 Bits" + Fore.RESET)
    if len(ciphertext) == 2732:
        print(Fore.BLUE + "[*] " + Fore.WHITE + "Key Length: 16384 Bits" + Fore.RESET)
        
    print(Fore.BLUE + "[*] " + Fore.WHITE + "Ciphertext: " + ciphertext.decode() + Fore.RESET)
    ciphertext = base64.b64decode(ciphertext)


    # Decrypt the ciphertext using the loaded private key
    decrypted_message = loaded_private_key.decrypt(
    ciphertext,
    padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
    ))
    print(Fore.BLUE + "[*] " + Fore.WHITE + "Decrypted Message: " + decrypted_message.decode('utf-8') + Fore.RESET)
except Exception as e:
    print(f"Error: {str(e)}")
