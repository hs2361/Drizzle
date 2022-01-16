from enum import Enum
from typing import NamedTuple, TypedDict


class HeaderCode(Enum):
    ERROR = "e"
    FILE = "f"
    FILE_REQUEST = "F"
    FILE_SEARCH = "s"
    LOOKUP_ADDRESS = "l"
    MESSAGE = "m"
    NEW_CONNECTION = "n"
    REQUEST_UNAME = "r"
    SHARE_DATA = "d"
    UPDATE_HASH = "h"


class CompressionMethod(Enum):
    NONE = 0
    ZSTD = 1


class Message(TypedDict):
    type: HeaderCode
    query: bytes


class FileMetadata(TypedDict):
    name: str
    size: int
    hash: str | None
    compression: CompressionMethod


class FileRequest(TypedDict):
    filepath: str
    port: int
    request_hash: bool


class FileSearchResult(NamedTuple):
    uname: str
    filepath: str
    filesize: int
    hash: str


class UpdateHashParams(TypedDict):
    filepath: str
    hash: str
