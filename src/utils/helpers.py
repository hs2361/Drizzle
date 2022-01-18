import hashlib
import logging
import os
from pathlib import Path

from utils.constants import HASH_BUFFER_LEN, RECV_FOLDER_PATH, SHARE_FOLDER_PATH
from utils.types import CompressionMethod, DirData, FileMetadata


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
            shareable_files.append({"name": str(fname), "size": fname.stat().st_size})
    return shareable_files


def get_unique_filename(path: Path) -> Path:
    filename, extension = path.stem, path.suffix
    counter = 1

    while path.exists():
        path = RECV_FOLDER_PATH / Path(filename + "_" + str(counter) + extension)
        counter += 1

    logging.debug(f"unique file name is {path}")
    return path
