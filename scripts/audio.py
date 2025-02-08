from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pydub import AudioSegment
import os

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


def encrypt_audio(symmetric_key, audio_data):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    encryptor = cipher.encryptor()

    encrypted_data = encryptor.update(audio_data) + encryptor.finalize()

    return iv + encrypted_data
    

# def encrypt_audio(input_filename, output_filename, symmetric_key):
#     audio = AudioSegment.from_file(input_filename, format="wav")

#     iv = os.urandom(16)
#     cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
#     encryptor = cipher.encryptor()

#     encrypted_audio = AudioSegment.silent(duration=0)

#     buffer_size = 8192
#     for i in range(0, len(audio.raw_data), buffer_size):
#         chunk = audio.raw_data[i:i + buffer_size]
#         encrypted_chunk = encryptor.update(chunk)
#         encrypted_audio += AudioSegment(encrypted_chunk, sample_width=2, frame_rate=audio.frame_rate, channels=audio.channels)

#     encrypted_audio.export(output_filename, format="wav")

# def decrypt_audio(input_filename, output_filename, symmetric_key):
#     encrypted_audio = AudioSegment.from_file(input_filename, format="wav")

#     iv = os.urandom(16)
#     cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
#     decryptor = cipher.decryptor()

#     decrypted_audio = AudioSegment.silent(duration=0)

#     buffer_size = 8192
#     for i in range(0, len(encrypted_audio.raw_data), buffer_size):
#         chunk = encrypted_audio.raw_data[i:i + buffer_size]
#         decrypted_chunk = decryptor.update(chunk)
#         decrypted_audio += AudioSegment(decrypted_chunk, sample_width=2, frame_rate=encrypted_audio.frame_rate, channels=encrypted_audio.channels)

#     decrypted_audio.export(output_filename, format="wav")

def decrypt_audio(symmetric_key, encrypted_data):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    decryptor = cipher.decryptor()

    decrypted_audio = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_audio


def main():
    
    while True:
        ch = int(input("Enter 1 for encrypt, 2 for decrypt, 3 for exit: "))
        if ch == 1:
            private_key, public_key = generate_key_pair()
            input_filename = input("Enter the input audio file name (WAV format): ")
            output_filename = input("Enter the output encrypted audio file name (WAV format): ")
            symmetric_key = derive_symmetric_key(public_key, private_key)
            encrypt_audio(input_filename, output_filename, symmetric_key)
            print("Audio file encrypted successfully.")
        elif ch == 2:
            input_filename = input("Enter the input encrypted audio file name (WAV format): ")
            output_filename = input("Enter the output decrypted audio file name (WAV format): ")
            symmetric_key = derive_symmetric_key(public_key, private_key)
            decrypt_audio(input_filename, output_filename, symmetric_key)
            print("Audio file decrypted successfully.")
        elif ch == 3:
            exit(0)
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()

'''

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pydub import AudioSegment
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

def encrypt_audio(input_filename, output_filename, symmetric_key):
    audio = AudioSegment.from_file(input_filename, format="mp3")

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    encryptor = cipher.encryptor()

    encrypted_audio = AudioSegment.silent(duration=0)

    buffer_size = 8192
    for i in range(0, len(audio.raw_data), buffer_size):
        chunk = audio.raw_data[i:i + buffer_size]
        encrypted_chunk = encryptor.update(chunk)
        encrypted_audio += AudioSegment(encrypted_chunk, frame_rate=audio.frame_rate, channels=audio.channels)

    encrypted_audio.export(output_filename, format="mp3")

def decrypt_audio(input_filename, output_filename, symmetric_key):
    encrypted_audio = AudioSegment.from_file(input_filename, format="mp3")

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    decryptor = cipher.decryptor()

    decrypted_audio = AudioSegment.silent(duration=0)

    buffer_size = 8192
    for i in range(0, len(encrypted_audio.raw_data), buffer_size):
        chunk = encrypted_audio.raw_data[i:i + buffer_size]
        decrypted_chunk = decryptor.update(chunk)
        decrypted_audio += AudioSegment(decrypted_chunk, frame_rate=encrypted_audio.frame_rate, channels=encrypted_audio.channels)

    decrypted_audio.export(output_filename, format="mp3")

def main():
    
    while True:
        ch = int(input("Enter 1 for encrypt, 2 for decrypt, 3 for exit: "))
        if ch == 1:
            private_key, public_key = generate_key_pair()
            input_filename = input("Enter the input audio file name (MP3 format): ")
            output_filename = input("Enter the output encrypted audio file name (MP3 format): ")
            symmetric_key = derive_symmetric_key(public_key, private_key)
            encrypt_audio(input_filename, output_filename, symmetric_key)
            print("Audio file encrypted successfully.")
        elif ch == 2:
            input_filename = input("Enter the input encrypted audio file name (MP3 format): ")
            output_filename = input("Enter the output decrypted audio file name (MP3 format): ")
            symmetric_key = derive_symmetric_key(public_key, private_key)
            decrypt_audio(input_filename, output_filename, symmetric_key)
            print("Audio file decrypted successfully.")
        elif ch == 3:
            exit(0)
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()

'''