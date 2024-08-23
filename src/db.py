import sqlite3
from logger import get_logger
# from service import handle_new_password

logger = get_logger(__name__)


DB_FILE = "passwords.db"


def create_database():
    """Creates the database and table if they don't exist."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL)"""
        )
        conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Error creating database: {e}")
    finally:
        conn.close()


def save_password(title: str, password: str):
    """Saves a single password to the SQLite database."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO passwords (title, password) VALUES (?, ?)", (title, password)
        )
        conn.commit()
        logger.info("Password saved successfully!")

    except sqlite3.IntegrityError:
        logger.error(
            f"Error saving password: The password for title '{title}' already exists.")
        # handle_new_password()

    except sqlite3.Error as e:
        logger.error(f"Error saving password: {e}")
    finally:
        conn.close()


def get_passwprd_by_title(title: str) -> str:
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(
            f"SELECT password from passwords WHERE title = '{title}'"
        )
        password = cursor.fetchone()
        return password[0]
    except sqlite3.Error as e:
        logger.error(f"Error finding password: {e}")
    finally:
        conn.close()


def load_passwords():
    """Loads passwords from the SQLite database."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT id, title FROM passwords")
        passwords = cursor.fetchall()
        return passwords
    except sqlite3.Error as e:
        logger.error(f"Error loading passwords: {e}")
        return []
    finally:
        conn.close()
