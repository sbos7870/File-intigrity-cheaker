import os
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

def generate_key(password, salt=None):
    """Generates a Fernet key from a password."""
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  # Adjust iterations for security
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_file(filepath, password, output_filepath=None):
    """Encrypts a file using AES-256 (via Fernet)."""
    try:
        key, salt = generate_key(password)
        f = Fernet(key)
        with open(filepath, 'rb') as file:
            file_data = file.read()
        encrypted_data = f.encrypt(file_data)
        if output_filepath is None:
            output_filepath = filepath + ".enc"

        with open(output_filepath, 'wb') as encrypted_file:
            encrypted_file.write(salt + encrypted_data) #Store the salt with the encrypted data.

        print(f"File encrypted successfully: {output_filepath}")
        return True

    except Exception as e:
        print(f"Encryption error: {e}")
        return False

def decrypt_file(filepath, password, output_filepath=None):
    """Decrypts a file encrypted with AES-256 (via Fernet)."""
    try:
        with open(filepath, 'rb') as encrypted_file:
            encrypted_data_with_salt = encrypted_file.read()
            salt = encrypted_data_with_salt[:16] #Retrieve the salt.
            encrypted_data = encrypted_data_with_salt[16:]
        key, _ = generate_key(password, salt) #Use the stored salt.
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data)

        if output_filepath is None:
            output_filepath = filepath.replace(".enc", "") if filepath.endswith(".enc") else filepath + ".dec" #handles both .enc and .dec extensions.

        with open(output_filepath, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        print(f"File decrypted successfully: {output_filepath}")
        return True

    except Exception as e:
        print(f"Decryption error: {e}")
        return False


def main():
    """Main function to handle user interaction."""
    import argparse

    parser = argparse.ArgumentParser(description="Advanced Encryption Tool")
    parser.add_argument("action", choices=["encrypt", "decrypt"], help="Encrypt or decrypt")
    parser.add_argument("filepath", help="Path to the file")
    parser.add_argument("password", help="Password for encryption/decryption")
    parser.add_argument("-o", "--output", help="Output file path (optional)")

    args = parser.parse_args()

    if args.action == "encrypt":
        encrypt_file(args.filepath, args.password, args.output)
    elif args.action == "decrypt":
        decrypt_file(args.filepath, args.password, args.output)

if __name__ == "__main__":
    main()

"""
Usage:
python encryption_tool.py encrypt <filepath> <password> [-o <output_filepath>]
python encryption_tool.py decrypt <filepath> <password> [-o <output_filepath>]

Example:
python encryption_tool.py encrypt my_secret.txt mysecretpassword -o my_secret.txt.enc
python encryption_tool.py decrypt my_secret.txt.enc mysecretpassword -o my_secret_decrypted.txt
"""