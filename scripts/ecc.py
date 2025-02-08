'''import key_gen
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import key_gen as kg

def derive_symmetric_key(public_key, private_key):
    shared_key = private_key.exchange(ec.ECDH(), public_key)
   
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=b"salt",
        length=32
    )
    return kdf.derive(shared_key)

def encrypt_message(symmetric_key, message):
    iv = b"1234567890123456"
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CTR(iv))
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode('utf-8')) + padder.finalize()
   
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(symmetric_key, ciphertext):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
   
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CTR(iv))
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
   
    return decrypted_data.decode('utf-8')

def main():
    while True:
        ch = int(input("Enter 1 for encrypt 2 for decrypt 3 for exit:"))
        if ch == 1:
            message = input("Enter the message to encrypt: ")
            public_key = input("Enter the public key:")
            symmetric_key = derive_symmetric_key(public_key, kg.private_key)
            print(symmetric_key)
            ciphertext = encrypt_message(symmetric_key, message)
            print("Ciphertext:", ciphertext.hex())
        
        elif ch == 2:
            try:
                ciphertext = bytes.fromhex(input("Enter the ciphertext (in hex format): "))
                public_key = input("Enter the public key:")
                symmetric_key = derive_symmetric_key(public_key, kg.private_key)
                print(symmetric_key)
                decrypted_message = decrypt_message(symmetric_key, ciphertext)
                print("Decrypted Message:", decrypted_message)
            except:
                print("Invalid hex format. Please enter correct format")
 
        else:
            #print("Invalid action. Please choose 'encrypt' or 'decrypt'.")
            exit(0) 

if __name__ == "__main__":
    main()

'''

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from tinyec import registry, ec
import secrets
from tinyec import registry
import secrets
from Crypto.Cipher import AES
from tinyec import ec, registry
import hashlib
import binascii
import base64
import io

curve = registry.get_curve('brainpoolP256r1')

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()


def derive_symmetric_key(pubKey, ciphertextPrivKey):
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    return secretKey

def encrypt_message(symmetric_key, message):
    iv = b"1234567890123456"
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CTR(iv))
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode('utf-8')) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(symmetric_key, ciphertext):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]

    cipher = Cipher(algorithms.AES(symmetric_key), modes.CTR(iv))
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data.decode('utf-8')
'''
def main():
    while True:
        ch = int(input("Enter 1 for encrypt, 2 for decrypt, 3 for exit: "))
        if ch == 1:
            message = input("Enter the message to encrypt: ")
            pubx=input("Enter the public key x: ")
            puby=input("Enter the public key y: ")
            priv=input("Enter the private key: ")
            private_key = int(priv)
            publicx = int(pubx)
            publicy = int(puby)
            public_key = ec.Point(curve,publicx,publicy)
            symmetric_key = derive_symmetric_key(public_key, private_key)
            ciphertext = encrypt_message(symmetric_key, message)
            print("Ciphertext:", ciphertext.hex())

        elif ch == 2:
            try:
                ciphertext = bytes.fromhex(input("Enter the ciphertext (in hex format): "))
                pubx=input("Enter the public key x: ")
                puby=input("Enter the public key y: ")
                priv=input("Enter the private key: ")
                private_key = int(priv)
                publicx = int(pubx)
                publicy = int(puby)
                public_key = ec.Point(curve,publicx,publicy)
                symmetric_key = derive_symmetric_key(public_key, private_key)
                decrypted_message = decrypt_message(symmetric_key, ciphertext)
                print("Decrypted Message:", decrypted_message)
            except:
                print("Invalid hex format or key. Please enter correct format and key.")
        else:
            exit(0) 

if __name__ == "__main__":
    main()

'''