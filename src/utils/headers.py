from enum import Enum


class HeaderCode(Enum):
    NEW_CONNECTION = "n"
    REQUEST_UNAME = "r"
    LOOKUP_ADDRESS = "l"
    ERROR = "e"
    MESSAGE = "m"
    FILE = "f"
