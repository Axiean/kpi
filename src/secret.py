

from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from hashing import validate_hashed_key
from logger import get_logger

logger = get_logger(__name__)


SECRET_FILE = "secret.key"
ITERATIONS = 390000


def derive_key(key: str, salt: bytes) -> bytes:
    """Derives a cryptographic key from a password and salt using PBKDF2.

    Args:
        key: The input password to derive the key from.
        salt: The salt to use for key derivation.

    Returns:
        The derived cryptographic key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(key.encode())


def read_stored_secret_key() -> str:
    """Reads the content of the secret key file.

    Args:
        filename: The path to the secret key file.

    Returns:
        The content of the secret key as a string.
    """
    try:
        with open(SECRET_FILE, "r") as file:
            secret_key_content = file.read().strip()
        return secret_key_content
    except FileNotFoundError:
        logger.error(f"The file '{SECRET_FILE}' was not found.")
        return None
    except IOError as e:
        logger.error(f"Error reading file '{SECRET_FILE}': {e}")
        return None


def ask_for_secret(max_attempts=3) -> bool | str:
    """Prompt the user to enter a secret key and validate it.

    Args:
        max_attempts (int): Maximum number of attempts allowed for entering the secret key.

    Returns:
        bool: True if the secret key is valid, False otherwise.
    """
    for attempt in range(1, max_attempts + 1):
        entered_secret = getpass("Enter Secret key: ")
        stored_secret = read_stored_secret_key()
        if validate_hashed_key(entered_secret, stored_secret):
            return entered_secret
        else:
            logger.error(
                f"Incorrect secret key. Attempt {attempt} of {max_attempts}.")

    logger.error("Maximum attempts exceeded. Access denied.")
    return False
