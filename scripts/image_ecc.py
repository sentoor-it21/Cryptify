'''from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
from PIL import Image

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

def encrypt_image(symmetric_key, input_image_path, output_image_path):
    # Load the input image
    input_image = Image.open(input_image_path)
    image_format = input_image.format

    # Convert the image to bytes
    with open(input_image_path, "rb") as img_file:
        image_bytes = img_file.read()

    # Encrypt image bytes using AES-CTR
    iv = b"1234567890123456"
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CTR(iv))
    encryptor = cipher.encryptor()

    encrypted_image_bytes = encryptor.update(image_bytes) + encryptor.finalize()

    # Save the encrypted image
    with open(output_image_path, "wb") as encrypted_img_file:
        encrypted_img_file.write(encrypted_image_bytes)

def decrypt_image(symmetric_key, encrypted_image_path, output_image_path):
    # Load the encrypted image bytes
    with open(encrypted_image_path, "rb") as encrypted_img_file:
        encrypted_image_bytes = encrypted_img_file.read()

    # Decrypt image bytes using AES-CTR
    iv = b"1234567890123456"
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CTR(iv))
    decryptor = cipher.decryptor()

    decrypted_image_bytes = decryptor.update(encrypted_image_bytes) + decryptor.finalize()

    # Determine the image format based on the file extension
    if encrypted_image_path.lower().endswith('.png'):
        image_format = 'PNG'
    elif encrypted_image_path.lower().endswith('.jpg') or encrypted_image_path.lower().endswith('.jpeg'):
        image_format = 'JPEG'
    elif encrypted_image_path.lower().endswith('.jfif'):
        image_format = 'JPEG'
    elif encrypted_image_path.lower().endswith('.gif'):
        image_format = 'GIF'
    else:
        print("Unsupported image format")

    # Save the decrypted image
    with open(output_image_path, "wb") as decrypted_img_file:
        decrypted_img_file.write(decrypted_image_bytes)

def main():
    
    while True:
        ch = int(input("Enter 1 for encrypt image, 2 for decrypt image, 3 for exit:"))
        if ch == 1:
            private_key, public_key = generate_key_pair()
            input_image_path = input("Enter the path of the input image: ")
            output_image_path = input("Enter the path for the encrypted image: ")
            symmetric_key = derive_symmetric_key(public_key, private_key)
            encrypt_image(symmetric_key, input_image_path, output_image_path)
            print("Image encrypted and saved.")
        
        elif ch == 2:
            encrypted_image_path = input("Enter the path of the encrypted image: ")
            output_image_path = input("Enter the path for the decrypted image: ")
            symmetric_key = derive_symmetric_key(public_key, private_key)
            decrypt_image(symmetric_key, encrypted_image_path, output_image_path)
            print("Image decrypted and saved.")
 
        else:
            exit(0)

if __name__ == "__main__":
    main()
'''

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from tinyec import registry,ec
import hashlib
from PIL import Image
import os


curve = registry.get_curve('brainpoolP256r1')


def derive_symmetric_key(pubKey, ciphertextPrivKey):
    sharedECCKey = ciphertextPrivKey * pubKey
    sha256 = hashlib.sha256()
    sha256.update(sharedECCKey.x.to_bytes(32, 'big'))
    sha256.update(sharedECCKey.y.to_bytes(32, 'big'))
    return sha256.digest()


def encrypt_image(symmetric_key, image_data):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    encryptor = cipher.encryptor()

    encrypted_data = encryptor.update(image_data) + encryptor.finalize()
    
    return iv + encrypted_data

# Decrypt image data
def decrypt_image(symmetric_key, encrypted_data):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_data
'''
def main():
    while True:
        ch = int(input("Enter 1 for encrypt, 2 for decrypt, 3 for exit: "))
        if ch == 1:
            image_path = input("Enter the path to the image file: ")
            pubx = int(input("Enter the recipient's public key x: "))
            puby = int(input("Enter the recipient's public key y: "))
            priv = int(input("Enter your private key: "))
            private_key = int(priv)
            public_key = ec.Point(curve, pubx, puby)
            symmetric_key = derive_symmetric_key(public_key, private_key)

            with open(image_path, 'rb') as file:
                image_data = file.read()

            encrypted_image = encrypt_image(symmetric_key, image_data)

            output_path = 'encrypted_image' + os.path.splitext(image_path)[1]
            with open(output_path, 'wb') as file:
                file.write(encrypted_image)

            print("Image encrypted and saved as '{}'.".format(output_path))

        elif ch == 2:
            try:
                encrypted_image_path = input("Enter the path to the encrypted image file: ")
                pubx = int(input("Enter the sender's public key x: "))
                puby = int(input("Enter the sender's public key y: "))
                priv = int(input("Enter your private key: "))
                private_key = int(priv)
                public_key = ec.Point(curve, pubx, puby)
                symmetric_key = derive_symmetric_key(public_key, private_key)

                with open(encrypted_image_path, 'rb') as file:
                    encrypted_image_data = file.read()

                decrypted_image_data = decrypt_image(symmetric_key, encrypted_image_data)

                output_path = 'decrypted_image' + os.path.splitext(encrypted_image_path)[1]
                with open(output_path, 'wb') as file:
                    file.write(decrypted_image_data)

                print("Image decrypted and saved as '{}'.".format(output_path))
            except:
                print("Invalid input or key. Please enter correct input and key.")

        else:
            exit(0)

if __name__ == "__main__":
    main()

'''