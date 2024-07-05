import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# Function to derive a key from the master password and salt
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Function to encrypt data
def encrypt(data: str, key: bytes) -> str:
    iv = os.urandom(16)  # Generate a random 16-byte IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    encrypted = encryptor.update(data.encode()) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode()

# Function to decrypt data
def decrypt(encrypted_data: str, key: bytes) -> str:
    encrypted_data = base64.b64decode(encrypted_data.encode())
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    return decrypted.decode()