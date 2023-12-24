from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
from colorama import Fore

print(Fore.RED + """
┳┓┏┓┏┓  ┳┓┏┓┏┓┳┓┓┏┏┓┏┳┓┏┓┳┓
┣┫┗┓┣┫  ┃┃┣ ┃ ┣┫┗┫┃┃ ┃ ┣ ┣┫
┛┗┗┛┛┗  ┻┛┗┛┗┛┛┗┗┛┣┛ ┻ ┗┛┛┗ """ + Fore.WHITE + "Decrypt Messages with RSA V1.0 Developed by " + Fore.GREEN + "ENVY IT GROUP" + Fore.RESET)

def load_private_key_from_file(filename):
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key
    
# Load keys from files
loaded_private_key = load_private_key_from_file("private_key.pem")


try:
    ciphertext = """KNGFaTJXb6RPuqFkIpl2xKIb75jalkSAbjxhJiYyM6PuuiIurRAYjj+J3F75k/E7quDa7taWWOe/wxzAfqB759XMpLtwDlwlyStUpwfb7rBaRs2WAr7Y73V2ux85XO1KWlgUcBbsTKESnyziooiJukgMhlX/OI6c2AdRo6FACV0+Y/HxAQBPyGkt49OlPu43k9pVOKaaMAfQi88mZaQd7bpXix/rlJ4S6Wq1MsSVYxM1T7v7jwWDLOYl1wffratnTak2FzlMJTLgX4CeZbBjDCwImecpRdNzt0/LGnCDtNC1NB92BWn+XnXDax+s16g52PDVynLL23EbUH9HJec9LnEy27owNY8D3F8XTkBcYVW22kW1Gl2sqmFzesZI7BXxv8cuHC/BvgiCGmj49XJuy5DvgDS3SCSPrxuHRK8fiQsHTchBiMrieY0ws/4bLd+cT9jeG3eckAj5TWeVpNvUTX3eue4IDqLLAUr3mKXsYKm1dj8Z0krGHNly1ek0zaaRcBcjbt8mtasOwVPm2j1xWhZLh9SuPumYkmXxlRaJDvrpnu0548AoHj+l7PG39M+6txiwtWjsCaCWOFp6K4+MwrKt4vLosl0rVM60BiqefQsNaMglhOuvv2qmCPt+FH2v1ocXfxAW3bJeAAhRYbqIjOz6qBwyG4f0nlXExMMrdE4="""

    print(Fore.BLUE + "[Ciphertext] " + Fore.WHITE + ciphertext + Fore.RESET)
    ciphertext = base64.b64decode(ciphertext)

    # Decrypt the ciphertext using the loaded private key
    print(Fore.BLUE + "[Status] " + Fore.WHITE + "Decrypting Message" +  Fore.RESET)
    decrypted_message = loaded_private_key.decrypt(
    ciphertext,
    padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
    ))
    print(Fore.BLUE + "[Decrypted message]" + Fore.RESET, Fore.WHITE + decrypted_message.decode('utf-8'))
except Exception as e:
    print(Fore.BLUE + "[Error] " + Fore.WHITE + f"{str(e)}")
