import hashlib
import logging
import math
import os
import re
from pathlib import Path

from utils.constants import HASH_BUFFER_LEN, TEMP_FOLDER_PATH  # MESSAGE_MAX_LEN,
from utils.types import CompressionMethod, DirData, ItemSearchResult, Message, TransferProgress, TransferStatus


def generate_transfer_progress() -> dict[Path, TransferProgress]:
    """Generate transfer progress data in absence of dump.

    Parses the user's tmp folder to find offsets for incommplete files.

    Returns
    -------
    dict[Path, TransferProgress]
        Returns transfer progress dictionary as generated
    """
    transfer_progress: dict[Path, TransferProgress] = {}
    for root, _, files in os.walk(str(TEMP_FOLDER_PATH)):
        for file in files:
            path = Path(root).joinpath(file)
            transfer_progress[path] = {
                "progress": path.stat().st_size,
                "status": TransferStatus.PAUSED,
            }
    return transfer_progress


def path_to_dict(path: Path, share_folder_path: str) -> DirData:
    """Converts a given folder path to a dictionary representation of the entire directory structure

    Recursively constructs the output dictionary.
    Works relative to the user's share folder.

    Parameters
    ----------
    path : Path
        Path to an item to be added to dictionary
    share_folder_path : str
        string path to user's share directory which contains the item at [path]

    Returns
    -------
    DirData
        Returns dictionary representation as defined by the DirData custom type
    """
    d: DirData = {
        "path": str(path).removeprefix(share_folder_path + "/"),
        "name": path.name,
        "hash": None,
        "compression": CompressionMethod.NONE.value,
        "type": "",
        "size": None,
        "children": [],
    }
    if path.is_dir():
        d["type"] = "directory"
        d["children"] = [path_to_dict(item, share_folder_path) for item in path.iterdir()]
    else:
        d["type"] = "file"
        d["size"] = Path(path).stat().st_size

    return d


def get_files_in_dir(dir: list[DirData] | None, files: list[DirData]):
    """Obtain only the file items in a given directory dictionary

    Recursively parses dictionary to obtain file items.
    Output is given in the [files] parameter.

    Parameters
    ----------
    dir : list[DirData]
        Directory structure starting from immediate children of the desired folder.
    files : list[DirData]
        Empty list which holds the output of this function.
    """
    if dir is None:
        return
    for item in dir:
        if item["type"] == "file":
            files.append(item)
        else:
            get_files_in_dir(item["children"], files)


def item_search(dir: list[DirData] | None, items: list[ItemSearchResult], search_query: str, owner: str):
    """Item search utility.

    Recurses a given file structure of a directory to find items that match a search string.
    On each item, the function performs a regex search for exact matches followed by a fuzzy search to capture potential spelling errors.
    Output is given in the [items] parameter.

    Parameters
    ----------
    dir : list[DirData]
        Directory structure starting from immediate children of the desired folder.
    items : list[ItemSearchResult]
        Empty list which holds the search results.
    search_query : str
        User provided keyword used for the search process.
    owner : str
        Username of the owner of given [dir]

    """
    from fuzzysearch import find_near_matches

    if dir is None:
        return
    for item in dir:
        if re.search(search_query, item["name"].lower()) is not None or find_near_matches(
            search_query, item["name"].lower(), max_l_dist=1
        ):
            items.append(
                {
                    "owner": owner,
                    "data": item,
                }
            )
        if item["type"] == "directory":
            item_search(item["children"], items, search_query, owner)


def display_share_dict(share: list[DirData] | None, indents: int = 0):
    """Utility to print a dir structure to stdout"""
    if share is None:
        return
    for item in share:
        if item["type"] == "file":
            print("    " * indents + item["name"])
        else:
            print("    " * indents + item["name"] + "/")
            display_share_dict(item["children"], indents + 1)


def update_file_hash(share: list[DirData], file_path: str, new_hash: str):
    """Utility to set a new hash value for a specified item in a dir structure.

    Recurses a given folder structure and updates the hash attribute when the specified item is found.

    Parameters
    ----------
    share : list[DirData]
        Dir structure that comntains item to update
    file_path : str
        Path attribute of item to update
    new_hash: str
        New hash value to be set
    """
    for item in share:
        if item["type"] == "file" and item["path"] == file_path:
            item["hash"] = new_hash
            return
        elif item["children"]:
            update_file_hash(item["children"], file_path, new_hash)
    return


def find_file(share: list[DirData] | None, path: str) -> DirData | None:
    """Utility to find a file item given the file path."""
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
    """Calculate hash for a given file on disk.

    Reads the given file in chunks and calculates a rolling hash for the same.

    Parameters
    ----------
    filepath : str
        Path to a file for which to calculate hash.
    """
    hash = hashlib.sha1()
    with open(filepath, "rb") as file:
        while True:
            file_bytes = file.read(HASH_BUFFER_LEN)
            hash.update(file_bytes)
            if len(file_bytes) < HASH_BUFFER_LEN:
                break
    return hash.hexdigest()


def get_unique_filename(path: Path) -> Path:
    """Utility to generate a unique filename if a desired name already exists on disk.

    Adds an incremental numeric suffix to the filename if the original or a previous iteration of the name exists in the user's downloads folder.
    Prevents accidental overwriting that may occur if different files happen to have the same name.

    Parameters
    ----------
    path : Path
        Desired path name for the file

    Returns
    -------
    Path
        Unique-ified path name for the file
    """
    parent, filename, extension = path.parent, path.stem, path.suffix
    counter = 1
    logging.debug(f"parent: {parent}")
    logging.debug(f"making unique file for {path}")
    while path.exists():
        path = parent / Path(filename + "_" + str(counter) + extension)
        counter += 1

    logging.debug(f"unique file name is {path}")
    return path


def get_pending_downloads(transfer_progress: dict[Path, TransferProgress]) -> str:
    """Utility to get a displayable string populated with incomplete downloads"""
    return "\n".join(
        [
            f"{str(file).removeprefix(str(TEMP_FOLDER_PATH) + '/')}: {progress['status'].name}"
            for (file, progress) in transfer_progress.items()
            if progress["status"] in [TransferStatus.DOWNLOADING, TransferStatus.PAUSED, TransferStatus.NEVER_STARTED]
        ]
    )


def get_directory_size(directory: DirData, size: int, count: int) -> tuple[int, int]:
    """Calculate directory size and contained files count for a given directory.

    Recurses a given directory to calculate the total size of the folder as well as the number of files present in it or its sub folders.

    Parameters
    ----------
    directory : DirData
        Directory structure for which to calculate the statistics
    size : int
        Parent level size value, helper param for recursive call
    count : int
        Parent level count value, helper param for recursive call

    Returns
    -------
    tuple[int, int]
        Returns a pair of calculated size, count
    """
    count = 0
    size = 0
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
    """Utility to generate symlink to a given file in the user's share folder path.

    Parameters
    ----------
    file_path : Path
        Path to a file for which symlink will be generated.
    share_folder_path : Path
        Path to user's share folder where the symlink will be saved.
    """
    if file_path.exists():
        imported_file = share_folder_path / file_path.name
        imported_file.symlink_to(file_path, target_is_directory=file_path.is_dir())
        return imported_file
    else:
        logging.error(f"Attempted to import file {str(file_path)} that does not exist")
        return None


def construct_message_html(message: Message, is_self: bool) -> str:
    """Utility to construct markup for a given message object.

    Parameters
    ----------
    message : Message
        A message object to be rendered.
    is_self : bool
        Boolean representing whether the sender of the given message is the current user.
        This is used for rendering a "You" in the markup instead of a sender username.

    Returns
    -------
    str
        Generated message html as a string
    """
    return f"""<p style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">
<span style=" font-weight:600; color:{'#1a5fb4' if is_self else '#e5a50a'};">{"You" if is_self else message["sender"]}: </span>
{message["content"]}
</p>
"""


def convert_size(size_bytes: int) -> str:
    """Utility to convert a size (bytes) value to a human readable string.

    Generates a size string suffixed with a unit like B, KB, MB and so on.

    Parameters
    ----------
    size_bytes : int
        Size to be converted as number of bytes

    Returns
    -------
    str
        Human readable size string
    """
    if size_bytes == 0:
        return "0B"
    size_name = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"]
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"
