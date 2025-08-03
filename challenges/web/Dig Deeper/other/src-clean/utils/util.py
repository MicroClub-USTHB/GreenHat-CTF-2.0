from unidecode import unidecode as clean_string
from uuid import uuid4


def generate_uuid():
    """
    Generates a unique identifier (UUID).
    """
    return str(uuid4())


def normalize_string(s: str) -> str:

    return clean_string(s.strip())


def generate_fake_flag() -> str:
    """
    Generates a fake flag for testing purposes.
    """
    return f"ghctf{{{generate_uuid()}}}"
