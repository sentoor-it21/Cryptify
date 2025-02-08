'''from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())  # Use desired ECC curve
    public_key = private_key.public_key()
    return private_key, public_key

def derive_symmetric_key(public_key, private_key):
    shared_key = private_key.exchange(ec.ECDH(), public_key)
   
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=b"salt",
        length=32
    )
    return kdf.derive(shared_key)

def encrypt_file(public_key, input_file_path, output_file_path):
    private_key, _ = generate_key_pair()

    # Read the input file
    with open(input_file_path, 'rb') as f:
        file_data = f.read()

    # Derive symmetric key
    symmetric_key = b'^\x99\xc2\xe2\x81\xdd\xe2\xa9\xda\x9a\xf4q\xffm\x02\xf3\x01\xb2A\xd8\x14#]\xfdOxN\xef\xe2\xcd\xd8\xf8'

    # Encrypt file data using AES-CTR
    iv = b"1234567890123456"
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CTR(iv))
    encryptor = cipher.encryptor()

    encrypted_file_data = encryptor.update(file_data) + encryptor.finalize()

    # Save the encrypted file
    with open(output_file_path, 'wb') as f:
        f.write(encrypted_file_data)

def decrypt_file(private_key, encrypted_file_path, output_file_path):
    # Read the encrypted file
    with open(encrypted_file_path, 'rb') as f:
        encrypted_file_data = f.read()

    # Derive symmetric key
    symmetric_key = b'^\x99\xc2\xe2\x81\xdd\xe2\xa9\xda\x9a\xf4q\xffm\x02\xf3\x01\xb2A\xd8\x14#]\xfdOxN\xef\xe2\xcd\xd8\xf8'

    # Decrypt file data using AES-CTR
    iv = b"1234567890123456"
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CTR(iv))
    decryptor = cipher.decryptor()

    decrypted_file_data = decryptor.update(encrypted_file_data) + decryptor.finalize()

    # Save the decrypted file
    with open(output_file_path, 'wb') as f:
        f.write(decrypted_file_data)

def main():
    private_key, public_key = generate_key_pair()

    while True:
        ch = int(input("Enter 1 for encrypt file, 2 for decrypt file, 3 for exit:"))
        if ch == 1:
            input_file_path = input("Enter the path of the input file: ")
            output_file_path = input("Enter the path for the encrypted file: ")
            encrypt_file(public_key, input_file_path, output_file_path)
            print("File encrypted and saved.")
        
        elif ch == 2:
            encrypted_file_path = input("Enter the path of the encrypted file: ")
            output_file_path = input("Enter the path for the decrypted file: ")
            decrypt_file(private_key, encrypted_file_path, output_file_path)
            print("File decrypted and saved.")
 
        else:
            exit(0)

if __name__ == "__main__":
    main()

'''

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import path
import pydub
import os

def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())  # Use desired ECC curve
    public_key = private_key.public_key()
    return private_key, public_key

def derive_symmetric_key(public_key, private_key):
    shared_key = private_key.exchange(ec.ECDH(), public_key)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=b"salt",
        length=32
    )
    return kdf.derive(shared_key)

def encrypt_file(symmetric_key, file_data):

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    encryptor = cipher.encryptor()

    encrypted_data = encryptor.update(file_data) + encryptor.finalize()

    return iv + encrypted_data

def decrypt_file(symmetric_key, encrypted_data):
    iv = encrypted_data[:16]

    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    return decrypted_data
    
def main():

    while True:
        ch = int(input("Enter 1 for encrypt, 2 for decrypt, 3 for exit: "))
        if ch == 1:
            private_key, public_key = generate_key_pair()
            input_filename = input("Enter the input file name: ")
            output_filename = input("Enter the output encrypted file name: ")
            symmetric_key = derive_symmetric_key(public_key, private_key)
            encrypt_file(input_filename, output_filename, symmetric_key)
            print("File encrypted successfully.")
        elif ch == 2:
            input_filename = input("Enter the input encrypted file name: ")
            output_filename = input("Enter the output decrypted file name: ")
            symmetric_key = derive_symmetric_key(public_key, private_key)
            decrypt_file(input_filename, output_filename, symmetric_key)
            print("File decrypted successfully.")
        elif ch == 3:
            exit(0)
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()