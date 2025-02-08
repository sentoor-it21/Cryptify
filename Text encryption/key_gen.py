'''from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
global private_key,public_key
def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())  # Use desired ECC curve
    public_key = private_key.public_key()
    
    private_value = private_key.private_numbers().private_value
    public_value = public_key.public_numbers().y
    
    print("Private key:")
    print("Private value:", private_value)
    print("Private value as hex:", hex(private_value))
    
    print("\nPublic key:")
    print("Public value:", public_value)
    print("Public value as hex:", hex(public_value))
    
    return private_key, public_key

private_key, public_key=generate_key_pair()
'''

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from tinyec import registry, ec
import secrets

curve = registry.get_curve('brainpoolP256r1')

def generate_key_pair():
    privKey = secrets.randbelow(curve.field.n)
    pubKey = privKey * curve.g
    pubx = pubKey.x
    puby = pubKey.y
    print("Private key: ",privKey)
    print("Public key x: ",pubx)
    print("Public key y: ",puby)

generate_key_pair()