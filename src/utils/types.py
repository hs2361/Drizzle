from enum import Enum
from typing import NamedTuple, TypedDict


class HeaderCode(Enum):
    ERROR = "e"
    FILE = "f"
    FILE_REQUEST = "F"
    FILE_SEARCH = "s"
    REQUEST_UNAME = "R"
    MESSAGE = "m"
    NEW_CONNECTION = "n"
    REQUEST_IP = "r"
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


class DirData(TypedDict):
    name: str
    path: str
    type: str
    size: int | None
    hash: str | None
    compression: int
    children: list["DirData"] | None  # type: ignore


class UpdateHashParams(TypedDict):
    filepath: str
    hash: str


class DBData(TypedDict):
    uname: str
    share: list[DirData]


"""
share: [
    file1,
    file2,
    {
        folder1: [
            file3,
            {
                folder3: [
                    file4
                ]
            }
        ],
        folder2: []
    }
]
"""
