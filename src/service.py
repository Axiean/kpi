
from db import save_password, get_passwprd_by_title, load_passwords
from secret import read_stored_secret_key, ask_for_secret, validate_hashed_key
from encrypion import encrypt_string, decrypt_string
from hashing import hash_key
from getpass import getpass
import argparse
import sys
from logger import get_logger
import os

logger = get_logger(__name__)


SECRET_FILE = "secret.key"


def handle_new_password():
    """Handles user input for creating a new password entry."""

    title = input("Enter a title (or 'q' to quit): ")
    if title.lower() == 'q':
        logger.error("Exiting...")
        return

    password = getpass("Enter a password: ")
    entered_secret = getpass("Enter Secret key: ")
    stored_secret = read_stored_secret_key()

    valide_secret = validate_hashed_key(entered_secret, stored_secret)

    if not valide_secret:
        logger.error("Secret Key wrong!!")
        return

    encrypted_password = encrypt_string(password, entered_secret)
    save_password(title, encrypted_password)


def handle_show_passwords_list():
    """Handles displaying a list of stored passwords."""
    if ask_for_secret():
        all_passwords = load_passwords()
        if all_passwords:
            logger.info("All stored passwords:")
            for password in all_passwords:
                print(f"ID: {password[0]}, Title: {password[1]}")
        else:
            logger.info("No passwords found.")
    else:
        logger.error(
            "Failed to validate the secret key. Cannot display the passwords list.")


def handle_option_selection():

    option = input("Enter option number: ")
    if option:
        match option:
            case "1":
                handle_new_password()
            case "2":
                handle_show_passwords_list()
            case _:
                logger.error("Wrong Option Entered!\n")
                handle_option_selection()


def handle_show_single_password():
    """This method will decrypt and show stored password"""
    title = input("Enter youe password title: ")

    if not title:
        handle_show_single_password()
        return

    secret = ask_for_secret()
    password = get_passwprd_by_title(title)
    decrypted_password = decrypt_string(password, secret)

    logger.info(decrypted_password)

    return


class CustomArgumentParser(argparse.ArgumentParser):

    def error(self, message):
        # Override the default error handling to provide a custom message
        logger.error("Wrong command entered!")
        self.print_help()
        sys.exit(2)


def check_and_store_secret():
    """Checks if the secret file exists. If not, prompts the user to enter a secret and stores it."""
    if not os.path.exists(SECRET_FILE):
        secret = getpass("Enter the secret key: ")
        hashed_secret = hash_key(secret)
        try:
            with open(SECRET_FILE, "w") as f:
                f.write(hashed_secret)
            logger.info("Secret key saved successfully.")
        except IOError as e:
            logger.error(f"Error writing secret key to file: {e}")


def show_menu():
    print("Menu:")
    print("1. New Password")
    print("2. Show Passwords List")
    handle_option_selection()


def handle_arguments():
    """Handles command line arguments."""
    parser = CustomArgumentParser(description="KEEPI")
    parser.add_argument("command", choices=[
                        "new", "list", "get"], help="Command to execute", nargs="?")
    args = parser.parse_args()
    if len(sys.argv) == 1:
        show_menu()
    else:
        if args.command:
            match args.command:
                case "new":
                    handle_new_password()
                case "list":
                    handle_show_passwords_list()
                case "get":
                    handle_show_single_password()
                case _:
                    logger.error("Error: Invalid command.")
