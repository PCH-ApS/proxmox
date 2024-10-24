#!/usr/bin/env python3

import crypt
import getpass
import os
import hashlib

# Function to generate a hashed password
def hash_password(password: str) -> str:
    # Using SHA-512 hashing with a randomly generated salt
    salt = os.urandom(16).hex()[:16]
    hashed_password = crypt.crypt(password, f'$6${salt}$')
    return hashed_password

def main():
    # Prompt for password input securely
    password = getpass.getpass(prompt='Enter the password: ')
    hashed_password = hash_password(password)
    print("Hashed Password:", hashed_password)

if __name__ == "__main__":
    main()