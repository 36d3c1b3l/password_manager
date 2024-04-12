from cryptography.fernet import Fernet

from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import base64

def view(fer):
    
    loginfile = open('logins.txt', 'r')
    pwdfile =  open('passwords.txt', 'rb')
    for login in loginfile.readlines():
        try:
            data = login.rstrip()
            login, leng = data.split("|") 
            print(f"User: {login}")      
            token = pwdfile.read(int(leng))
            decr_token = fer.decrypt(token).decode()
            print(f"Password: {decr_token}")
        except InvalidToken:
            print("Invalid master password for this login")

def load_salt():
    # Implement this function to load the salt from persistent storage
    # For example, you could read the salt from a file
    with open("salt.txt", "rb") as file:
        return file.read()
    
def load_key(master_pwd):
    # Generate a random salt
    salt = load_salt()
    #print(salt)
    # Use PBKDF2HMAC to derive a key from the master password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_pwd.encode()))
    return key

def add(fer):
    
    name = input("Account Name: ")
    pwd = input("Password: ")
    token = fer.encrypt(pwd.encode())
    #token_base64 = base64.urlsafe_b64encode(token).decode()
    with open('logins.txt', 'a') as f:
        f.write(f"{name}|{len(token)}\n")
    with open('passwords.txt', 'ab') as f:
        f.write(token)

def main():
    master_pwd = input("What is the master password? ")
    key = load_key(master_pwd)
    fer = Fernet(key)
    
    while True:
        mode = input("Would you like to view existing passwords, add a new one or quit? (view/add/quit) ").lower()
        if mode == "quit":
            break

        if mode == "view":
            view(fer)
        elif mode == "add":
            add(fer)
        else:
            print("Invalid mode")
            



if __name__ == "__main__":
    main()