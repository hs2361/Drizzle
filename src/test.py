import threading
from concurrent.futures import ThreadPoolExecutor


def task(n):
    print("Processing {}".format(n))


def main():
    print("Starting ThreadPoolExecutor")
    x = list(range(100))
    with ThreadPoolExecutor() as executor:
        executor.map(task, x)
    print("All tasks complete")


if __name__ == "__main__":
    thread = threading.Thread(target=main, daemon=True)
    thread.start()
    # main()

# from pathlib import Path
# from typing import TypedDict

# from utils.helpers import (
#     display_share_dict,
#     get_files_in_dir,
#     path_to_dict,
#     update_file_hash,
# )


# class DirData(TypedDict):
#     name: str
#     type: str
#     size: int | None
#     hash: str | None
#     children: list["DirData"] | None  # type: ignore


# s = path_to_dict(Path("."))["children"]
# display_share_dict(s)

# print()

# l = []

# if s:
#     get_files_in_dir(s, l)
#     print(*l, sep="\n")
