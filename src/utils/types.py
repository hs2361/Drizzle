from enum import Enum
from typing import NamedTuple, TypedDict


# Communication header codes for Drizzle's protocol
class HeaderCode(Enum):
    ERROR = "e"
    DIRECT_TRANSFER_REQUEST = "t"
    DIRECT_TRANSFER = "T"
    FILE_REQUEST = "F"
    FILE_BROWSE = "b"
    FILE_SEARCH = "s"
    HEARTBEAT_REQUEST = "H"
    REQUEST_UNAME = "R"
    MESSAGE = "m"
    NEW_CONNECTION = "n"
    REQUEST_IP = "r"
    SHARE_DATA = "d"
    UPDATE_HASH = "h"
    UPDATE_SHARE_DATA = "D"


# Compression mode to be used
class CompressionMethod(Enum):
    NONE = 0
    ZSTD = 1


# Receiving status of a file
class TransferStatus(Enum):
    NEVER_STARTED = 0
    DOWNLOADING = 1
    PAUSED = 2
    COMPLETED = 3
    FAILED = 4


# File progress information
class TransferProgress(TypedDict):
    status: TransferStatus
    progress: int
    percent_progress: float


# Metadata for progress widgets
class ProgressBarData(TypedDict):
    current: int
    total: int


# Data available in a request received by server
class SocketMessage(TypedDict):
    type: HeaderCode
    query: bytes


# Metadata for a file item
class FileMetadata(TypedDict):
    path: str
    size: int
    hash: str | None
    compression: CompressionMethod


# Information sent while requesting a file
class FileRequest(TypedDict):
    filepath: str
    port: int
    request_hash: bool
    resume_offset: int  # If part of file has been received previously


class FileSearchResult(NamedTuple):
    uname: str
    filepath: str
    filesize: int
    hash: str


# Directory structure (files and folders) data representation [recursive]
class DirData(TypedDict):
    name: str
    path: str
    type: str
    size: int | None
    hash: str | None
    compression: int
    children: list["DirData"] | None  # type: ignore


# Global search result data
class ItemSearchResult(TypedDict):
    owner: str
    data: DirData


# Hash updation data
class UpdateHashParams(TypedDict):
    filepath: str
    hash: str


# TinyDB document schema
class DBData(TypedDict):
    uname: str
    share: list[DirData]


# User settings dictionary/json format
class UserSettings(TypedDict):
    uname: str
    server_ip: str
    share_folder_path: str
    downloads_folder_path: str
    show_notifications: bool


# Chat message object
class Message(TypedDict):
    sender: str
    content: str
