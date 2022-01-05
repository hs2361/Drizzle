from enum import Enum
from typing import TypedDict


class HeaderCode(Enum):
    NEW_CONNECTION = "n"
    REQUEST_UNAME = "r"
    LOOKUP_ADDRESS = "l"
    ERROR = "e"
    MESSAGE = "m"
    FILE = "f"


class Message(TypedDict):
    type: HeaderCode
    query: bytes
