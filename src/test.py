from pathlib import Path
from typing import TypedDict

from utils.helpers import display_share_dict, path_to_dict, update_file_hash


class DirData(TypedDict):
    name: str
    type: str
    size: int | None
    hash: str | None
    children: list["DirData"] | None  # type: ignore


s = path_to_dict(Path("."))["children"]
display_share_dict(s)

print()

if s:
    update_file_hash(s, "test.py", "newhash")
    display_share_dict(s)
