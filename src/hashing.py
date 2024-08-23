import hashlib
import secrets
from logger import get_logger

logger = get_logger(__name__)


def hash_key(key: str, iterations: int = 100000) -> str:
    """Hashes a secret key using SHA-256 with salt and iterations.

    Args:
        key: The secret key to hash.
        iterations: The number of iterations for the hashing process.

    Returns:
        The hashed key as a hexadecimal string with salt.
    """
    salt = secrets.token_bytes(16)
    hash_object = hashlib.sha256()
    hash_object.update(salt + key.encode())
    for _ in range(iterations):
        hash_object.update(hash_object.digest())
    hashed_key = hash_object.hexdigest() + salt.hex()
    return hashed_key


def validate_hashed_key(input_key: str, stored_hash: str, iterations: int = 100000) -> bool:
    """Validates the input key against the stored hash using SHA-256 with salt and iterations.

    Args:
        input_key: The secret key to validate.
        stored_hash: The stored hashed key, including the salt.
        iterations: The number of iterations used for the hashing process.

    Returns:
        True if the input key is valid (matches the stored hash), False otherwise.
    """
    # Extract the original salt from the stored hash (last 32 characters are salt in hex)
    salt_hex = stored_hash[-32:]
    salt = bytes.fromhex(salt_hex)

    # Extract the original hash without the salt
    original_hash = stored_hash[:-32]

    # Re-create the hash using the extracted salt and provided key
    hash_object = hashlib.sha256()
    hash_object.update(salt + input_key.encode())

    for _ in range(iterations):
        hash_object.update(hash_object.digest())

    # Compare the re-created hash to the stored hash
    new_hash = hash_object.hexdigest()

    return new_hash == original_hash
