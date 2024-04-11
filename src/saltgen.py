from cryptography.fernet import Fernet

from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import base64

def keygen():
    salt = os.urandom(16)
    with open("salt.txt", "wb") as key_file:
        key_file.write(salt)

if __name__ == "__main__":
    keygen()