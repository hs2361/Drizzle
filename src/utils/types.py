from enum import Enum
from typing import NamedTuple, TypedDict

from PyQt5.QtCore import QMutex


class HeaderCode(Enum):
    ERROR = "e"
    FILE = "f"
    FILE_REQUEST = "F"
    FILE_SEARCH = "s"
    HEARTBEAT_REQUEST = "H"
    REQUEST_UNAME = "R"
    MESSAGE = "m"
    NEW_CONNECTION = "n"
    REQUEST_IP = "r"
    SHARE_DATA = "d"
    UPDATE_HASH = "h"
    UPDATE_SHARE_DATA = "D"


class CompressionMethod(Enum):
    NONE = 0
    ZSTD = 1


class TransferStatus(Enum):
    NEVER_STARTED = 0
    DOWNLOADING = 1
    PAUSED = 2
    COMPLETED = 3
    FAILED = 4


class TransferProgress(TypedDict):
    status: TransferStatus
    progress: int
    percent_progress: float


class DirProgress(TypedDict):
    mutex: QMutex | None
    current: int
    total: int
    status: TransferStatus


class ProgressBarData(TypedDict):
    current: int
    total: int


class SocketMessage(TypedDict):
    type: HeaderCode
    query: bytes


class FileMetadata(TypedDict):
    path: str
    size: int
    hash: str | None
    compression: CompressionMethod


class FileRequest(TypedDict):
    filepath: str
    port: int
    request_hash: bool
    resume_offset: int


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


class UserSettings(TypedDict):
    uname: str
    server_ip: str
    share_folder_path: str
    downloads_folder_path: str


class Message(TypedDict):
    sender: str
    content: str
