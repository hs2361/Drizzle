from enum import Enum
from typing import NamedTuple, TypedDict


class HeaderCode(Enum):
    NEW_CONNECTION = "n"
    REQUEST_UNAME = "r"
    LOOKUP_ADDRESS = "l"
    ERROR = "e"
    MESSAGE = "m"
    FILE = "f"
    PORT_ALLOCATION = "p"
    SHARE_DATA = "d"
    FILE_SEARCH = "s"


class Message(TypedDict):
    type: HeaderCode
    query: bytes


class FileMetadata(TypedDict):
    name: str
    size: int


class FileSearchResult(NamedTuple):
    uname: str
    filepath: str
    filesize: int
