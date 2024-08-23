import logging
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


class CustomFormatter(logging.Formatter):
    """Custom logging formatter to add colors based on log level."""
    LEVEL_COLORS = {
        logging.ERROR: Fore.RED,
        logging.WARNING: Fore.YELLOW,
        logging.INFO: Fore.GREEN,
        logging.DEBUG: Fore.CYAN
    }

    def format(self, record):
        log_color = self.LEVEL_COLORS.get(record.levelno, "")
        log_msg = super().format(record)
        return f"{log_color}{log_msg}{Style.RESET_ALL}"


def get_logger(logger_name):
    """Creates and returns a logger."""
    logger = logging.getLogger(logger_name)
    # Set the logger level to DEBUG to capture all log levels
    logger.setLevel(logging.DEBUG)

    # Create console handler and set the custom formatter
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(
        CustomFormatter('%(levelname)s - %(message)s'))

    # Avoid adding multiple handlers if the logger is already configured
    if not logger.hasHandlers():
        logger.addHandler(console_handler)
        logger.propagate = False

    return logger
