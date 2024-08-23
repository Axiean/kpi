import base64
from cryptography.fernet import Fernet
from logger import get_logger
import os
from secret import derive_key

SALT_LENGTH = 16
logger = get_logger(__name__)


def encrypt_string(string: str, key: str) -> str:
    """Encrypts a string using AES-256 encryption.

    Args:
        string: The string to be encrypted.
        key: The encryption key (can be any string).

    Returns:
        The encrypted string.
    """
    salt = os.urandom(SALT_LENGTH)
    derived_key = derive_key(key, salt)
    cipher = Fernet(base64.urlsafe_b64encode(derived_key))
    encrypted_bytes = cipher.encrypt(string.encode())
    return base64.urlsafe_b64encode(salt + encrypted_bytes).decode()


def decrypt_string(encrypted_string: str, key: str) -> str:
    """Decrypts a string that was encrypted using AES-256 encryption.

    Args:
        encrypted_string: The encrypted string to be decrypted.
        key: The encryption key (must be the same as the one used for encryption).

    Returns:
        The decrypted string.
    """
    encrypted_data = base64.urlsafe_b64decode(encrypted_string.encode())
    salt = encrypted_data[:SALT_LENGTH]
    encrypted_bytes = encrypted_data[SALT_LENGTH:]
    derived_key = derive_key(key, salt)
    cipher = Fernet(base64.urlsafe_b64encode(derived_key))
    decrypted_bytes = cipher.decrypt(encrypted_bytes)
    return decrypted_bytes.decode()
