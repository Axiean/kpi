from service import handle_arguments, check_and_store_secret
from logger import get_logger
from db import create_database


logger = get_logger(__name__)


def main():
    """Main function to coordinate the execution of the password manager."""
    try:
        check_and_store_secret()
        create_database()
        handle_arguments()
    except KeyboardInterrupt:
        logger.info("\nBYE!")
        exit(0)


if __name__ == "__main__":
    main()
