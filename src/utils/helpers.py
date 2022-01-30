import hashlib
import logging
import math
import os
from pathlib import Path

from utils.constants import (  # MESSAGE_MAX_LEN,
    HASH_BUFFER_LEN,
    RECV_FOLDER_PATH,
    SHARE_FOLDER_PATH,
    TEMP_FOLDER_PATH,
)
from utils.types import CompressionMethod, DirData, FileMetadata, TransferProgress, TransferStatus

# from prompt_toolkit.validation import ValidationError, Validator


# class MessageLenValidator(Validator):
#     def validate(self, document) -> None:
#         text = document.text
#         if len(text) > MESSAGE_MAX_LEN:
#             raise ValidationError(
#                 message=f"Message is too long. Limit to {MESSAGE_MAX_LEN} characters"
#             )


def generate_transfer_progress() -> dict[Path, TransferProgress]:
    transfer_progress: dict[Path, TransferProgress] = {}
    for root, _, files in os.walk(str(TEMP_FOLDER_PATH)):
        for file in files:
            path = Path(root).joinpath(file)
            transfer_progress[path] = {
                "progress": path.stat().st_size,
                "status": TransferStatus.PAUSED,
            }
    return transfer_progress


def path_to_dict(path: Path) -> DirData:
    d: DirData = {
        "path": str(path).removeprefix(str(SHARE_FOLDER_PATH) + "/"),
        "name": path.name,
        "hash": None,
        "compression": CompressionMethod.NONE.value,
        "type": "",
        "size": None,
        "children": [],
    }
    if path.is_dir():
        d["type"] = "directory"
        d["children"] = [path_to_dict(item) for item in path.iterdir()]
    else:
        d["type"] = "file"
        d["size"] = Path(path).stat().st_size

    return d


def get_files_in_dir(dir: list[DirData] | None, files: list[DirData]):
    if dir is None:
        return
    for item in dir:
        if item["type"] == "file":
            files.append(item)
        else:
            get_files_in_dir(item["children"], files)


def display_share_dict(share: list[DirData] | None, indents: int = 0):
    if share is None:
        return
    for item in share:
        if item["type"] == "file":
            print("    " * indents + item["name"])
        else:
            print("    " * indents + item["name"] + "/")
            display_share_dict(item["children"], indents + 1)


def update_file_hash(share: list[DirData], file_path: str, new_hash: str):
    for item in share:
        if item["type"] == "file" and item["path"] == file_path:
            item["hash"] = new_hash
            return
        elif item["children"]:
            update_file_hash(item["children"], file_path, new_hash)
    return


def find_file(share: list[DirData] | None, path: str) -> DirData | None:
    if share is None:
        return None
    for item in share:
        if item["path"] == path:
            return item
        else:
            s = find_file(item["children"], path)
            if s is not None:
                return s
    return None


def get_file_hash(filepath: str) -> str:
    hash = hashlib.sha1()
    with open(filepath, "rb") as file:
        while True:
            file_bytes = file.read(HASH_BUFFER_LEN)
            hash.update(file_bytes)
            if len(file_bytes) < HASH_BUFFER_LEN:
                break
    return hash.hexdigest()


def get_sharable_files() -> list[FileMetadata]:
    shareable_files: list[FileMetadata] = []
    for (root, _, files) in os.walk(str(SHARE_FOLDER_PATH)):
        for f in files:
            fname = Path(root).joinpath(f)
            shareable_files.append(
                {
                    "path": str(fname),
                    "size": fname.stat().st_size,
                    "hash": None,
                    "compression": CompressionMethod.NONE,
                }
            )
    return shareable_files


def get_unique_filename(path: Path) -> Path:
    filename, extension = path.stem, path.suffix
    counter = 1

    while path.exists():
        path = RECV_FOLDER_PATH / Path(filename + "_" + str(counter) + extension)
        counter += 1

    logging.debug(f"unique file name is {path}")
    return path


def get_pending_downloads(transfer_progress: dict[Path, TransferProgress]) -> str:
    return "\n".join(
        [
            f"{str(file).removeprefix(str(TEMP_FOLDER_PATH) + '/')}: {progress['status'].name}"
            for (file, progress) in transfer_progress.items()
            if progress["status"]
            in [TransferStatus.DOWNLOADING, TransferStatus.PAUSED, TransferStatus.NEVER_STARTED]
        ]
    )


def get_directory_size(directory: DirData, size: int, count: int) -> tuple[int, int]:
    if directory["children"] is None:
        count += 1
        size += directory["size"]
    else:
        for child in directory["children"]:
            if child["type"] == "file":
                count += 1
                size += child["size"]
            else:
                child_size, child_count = get_directory_size(child, size, count)
                size += child_size
                count += child_count
    return size, count


def import_file_to_share(file_path: Path, share_folder_path: Path) -> Path | None:
    if file_path.exists():
        imported_file = share_folder_path / file_path.name
        imported_file.symlink_to(file_path, target_is_directory=file_path.is_dir())
        return imported_file
    else:
        logging.error(f"Attempted to import file {str(file_path)} that does not exist")
        return None


def convert_size(size_bytes: int) -> str:
    if size_bytes == 0:
        return "0B"
    size_name = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"]
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"
