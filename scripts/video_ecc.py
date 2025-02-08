from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from tinyec import registry, ec
import os
from moviepy.editor import VideoFileClip
import hashlib

curve = registry.get_curve('brainpoolP256r1')

def ecc_point_to_256_bit_key(point):
    sha = hashes.Hash(hashes.SHA256())
    sha.update(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.finalize()

def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())  # Use desired ECC curve
    public_key = private_key.public_key()
    return private_key, public_key

def derive_symmetric_key(pubKey, ciphertextPrivKey):
    sharedECCKey = ciphertextPrivKey * pubKey
    sha256 = hashlib.sha256()
    sha256.update(sharedECCKey.x.to_bytes(32, 'big'))
    sha256.update(sharedECCKey.y.to_bytes(32, 'big'))
    return sha256.digest()

def encrypt_video(symmetric_key, video_data):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    encryptor = cipher.encryptor()

    encrypted_data = encryptor.update(video_data) + encryptor.finalize()

    return iv + encrypted_data

def decrypt_video(symmetric_key, encrypted_data):

    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_data

def main():

    while True:
        ch = int(input("Enter 1 for encrypt, 2 for decrypt, 3 for exit: "))
        if ch == 1:
            private_key, public_key = generate_key_pair()
            input_filename = input("Enter the input video file name (MP4 format): ")
            output_filename = input("Enter the output encrypted video file name: ")
            symmetric_key = derive_symmetric_key(public_key, private_key)
            encrypt_video(input_filename, output_filename, symmetric_key)
            print("Video file encrypted successfully.")
        elif ch == 2:
            input_filename = input("Enter the input encrypted video file name: ")
            output_filename = input("Enter the output decrypted video file name (MP4 format): ")
            symmetric_key = derive_symmetric_key(public_key, private_key)
            decrypt_video(input_filename, output_filename, symmetric_key)
            print("Video file decrypted successfully.")
        elif ch == 3:
            exit(0)
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()



'''
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from tinyec import registry, ec
import os
from moviepy.editor import VideoFileClip

# Define the elliptic curve
curve = registry.get_curve('brainpoolP256r1')

def ecc_point_to_256_bit_key(point):
    sha = hashes.Hash(hashes.SHA256())
    sha.update(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.finalize()

def derive_symmetric_key(pubKey, ciphertextPrivKey):
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    return secretKey

def encrypt_video(symmetric_key, video_file):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    
    encrypted_frames = b''
    offset = 0
    while True:
        frame_data = video_file.read(1024)
        if not frame_data:
            break
        encryptor = cipher.encryptor()
        encrypted_frame = encryptor.update(frame_data) + encryptor.finalize()
        encrypted_frames += encrypted_frame
        offset += len(frame_data)

    return iv + encrypted_frames


def decrypt_video(symmetric_key, encrypted_data):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    
    decrypted_frames = b''
    offset = 0
    while offset < len(ciphertext):
        encrypted_frame = ciphertext[offset:offset + 1024]
        decryptor = cipher.decryptor()
        decrypted_frame = decryptor.update(encrypted_frame) + decryptor.finalize()
        decrypted_frames += decrypted_frame
        offset += len(encrypted_frame)

    return iv + decrypted_frames
'''

'''
def main():
    while True:
        ch = int(input("Enter 1 for encrypt, 2 for decrypt, 3 for exit: "))
        if ch == 1:
            video_path = input("Enter the path to the video file: ")
            pubx = int(input("Enter the recipient's public key x: "))
            puby = int(input("Enter the recipient's public key y: "))
            priv = int(input("Enter your private key: "))
            private_key = int(priv)
            public_key = ec.Point(curve,pubx, puby)

            shared_key = derive_symmetric_key(public_key, private_key)

            encrypted_video = encrypt_video(shared_key, video_path)

            output_path = 'encrypted_video' + os.path.splitext(video_path)[1]
            with open(output_path, 'wb') as file:
                file.write(encrypted_video)

            print("Video encrypted and saved as '{}'.".format(output_path))

        elif ch == 2:
            try:
                encrypted_video_path = input("Enter the path to the encrypted video file: ")
                pubx = int(input("Enter the sender's public key x: "))
                puby = int(input("Enter the sender's public key y: "))
                priv = int(input("Enter your private key: "))
                private_key = int(priv)
                public_key = ec.Point(curve,pubx, puby)

                shared_key = derive_symmetric_key(public_key, private_key)

                output_path = 'decrypted_video' + os.path.splitext(encrypted_video_path)[1]
                with open(encrypted_video_path, 'rb') as file:
                    encrypted_video_data = file.read()

                decrypt_video(shared_key, encrypted_video_data, output_path)
            except:
                print("Invalid input or key. Please enter correct input and key.")

        else:
            exit(0)

if __name__ == "__main__":
    main()

'''
