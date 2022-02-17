import hashlib
import logging
import pickle
import re
import select
import shutil
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from pprint import pformat

import msgpack
import tqdm
from prompt_toolkit.patch_stdout import StdoutProxy
from prompt_toolkit.shortcuts import PromptSession

sys.path.append("../../")
from utils.constants import (
    CLIENT_RECV_PORT,
    CLIENT_SEND_PORT,
    FILE_BUFFER_LEN,
    FMT,
    HEADER_MSG_LEN,
    HEADER_TYPE_LEN,
    HEARTBEAT_TIMER,
    ONLINE_TIMEOUT,
    RECV_FOLDER_PATH,
    SERVER_RECV_PORT,
    SHARE_FOLDER_PATH,
    TEMP_FOLDER_PATH,
)
from utils.exceptions import ExceptionCode, RequestException
from utils.helpers import (
    MessageLenValidator,
    display_share_dict,
    find_file,
    generate_transfer_progress,
    get_file_hash,
    get_files_in_dir,
    get_pending_downloads,
    get_unique_filename,
    path_to_dict,
)
from utils.socket_functions import recvall, request_ip
from utils.types import (
    CompressionMethod,
    DBData,
    DirData,
    FileMetadata,
    FileRequest,
    HeaderCode,
    TransferProgress,
    TransferStatus,
    UpdateHashParams,
)

SERVER_IP = ""
SERVER_ADDR = (SERVER_IP, SERVER_RECV_PORT)
CLIENT_IP = socket.gethostbyname(socket.gethostname())

# logging.basicConfig(filename=f"/logs/client_{CLIENT_IP}.log", level=logging.DEBUG)

client_send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # to connect to main server
client_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # to receive new connections
client_send_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
client_recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
client_send_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
client_recv_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
client_send_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 0)
client_recv_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 0)
client_send_socket.bind((CLIENT_IP, CLIENT_SEND_PORT))
client_recv_socket.bind((CLIENT_IP, CLIENT_RECV_PORT))

while True:
    try:
        SERVER_IP = input("Enter SERVER IP: ")
        SERVER_ADDR = (SERVER_IP, SERVER_RECV_PORT)
        client_send_socket.connect((SERVER_IP, SERVER_RECV_PORT))
        break
    except Exception as e:
        logging.error(e)
        print("\nNo server found at this IP. Try again.")
client_recv_socket.listen(5)
connected = [client_recv_socket]
transfer_progress: dict[Path, TransferProgress] = {}
uname_to_status: dict[str, int] = {}
my_username = ""


def send_heartbeat(client_send_socket: socket.socket, uname_to_status: dict[str, int]) -> None:
    # global client_send_socket
    # global uname_to_status
    heartbeat = HeaderCode.HEARTBEAT_REQUEST.value.encode(FMT)
    while True:
        time.sleep(HEARTBEAT_TIMER)
        client_send_socket.send(heartbeat)
        type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)

        if type == HeaderCode.HEARTBEAT_REQUEST.value:
            length = int(client_send_socket.recv((HEADER_MSG_LEN)).decode(FMT))
            msgpack.unpackb(client_send_socket.recv(length))

        else:
            raise RequestException(
                f"Server sent invalid message type in header: {type}",
                ExceptionCode.INVALID_HEADER,
            )


def prompt_username() -> str:
    global my_username
    my_username = input("Enter username: ")
    username = my_username.encode(FMT)
    username_header = f"{HeaderCode.NEW_CONNECTION.value}{len(username):<{HEADER_MSG_LEN}}".encode(
        FMT
    )
    client_send_socket.send(username_header + username)
    type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
    return type


def request_file(
    file_requested: DirData, uname: str, client_peer_socket: socket.socket, progress_bar: tqdm.tqdm
) -> str:
    global transfer_progress
    logging.debug(f"Requesting file, progress is {transfer_progress}")
    file_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    file_recv_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    file_recv_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 0)
    file_recv_socket.bind((CLIENT_IP, 0))
    file_recv_socket.listen()
    file_recv_port = file_recv_socket.getsockname()[1]

    offset = 0
    temp_path: Path = TEMP_FOLDER_PATH.joinpath(uname + "/" + file_requested["path"])
    logging.debug(f"Using temp path {str(temp_path)}")
    if temp_path.exists():
        offset = temp_path.stat().st_size

    logging.debug(f"Offset of {offset} bytes")
    request_hash = file_requested["hash"] is None
    file_request: FileRequest = {
        "port": file_recv_port,
        "filepath": file_requested["path"],
        "request_hash": request_hash,
        "resume_offset": offset,
    }

    file_req_bytes = msgpack.packb(file_request)
    file_req_header = (
        f"{HeaderCode.FILE_REQUEST.value}{len(file_req_bytes):<{HEADER_MSG_LEN}}".encode(FMT)
    )
    client_peer_socket.send(file_req_header + file_req_bytes)

    try:
        res_type = client_peer_socket.recv(HEADER_TYPE_LEN).decode(FMT)
        logging.debug(f"received header type {res_type} from sender")
        match res_type:
            case HeaderCode.FILE_REQUEST.value:
                sender, _ = file_recv_socket.accept()
                logging.debug(msg=f"Sender tried to connect: {sender.getpeername()}")
                res_type = sender.recv(HEADER_TYPE_LEN).decode(FMT)
                if res_type == HeaderCode.DIRECT_TRANSFER.value:
                    file_header_len = int(sender.recv(HEADER_MSG_LEN).decode(FMT))
                    file_header: FileMetadata = msgpack.unpackb(sender.recv(file_header_len))
                    logging.debug(msg=f"receiving file with metadata {file_header}")
                    # Check if free disk space is available
                    if shutil.disk_usage(str(RECV_FOLDER_PATH)).free > file_header["size"]:
                        final_download_path: Path = get_unique_filename(
                            RECV_FOLDER_PATH / file_header["path"]
                        )
                        try:
                            temp_path.parent.mkdir(parents=True, exist_ok=True)
                            file_to_write = temp_path.open("ab")
                            # transfer_progress[temp_path] = {}
                            logging.debug(f"Creating and writing to {temp_path}")
                            try:
                                byte_count = 0
                                hash = hashlib.sha1()
                                logging.debug(
                                    msg=f"transfer progress for {str(temp_path)} is {transfer_progress[temp_path]}"
                                )
                                if (
                                    transfer_progress[temp_path].get(
                                        "status", TransferStatus.NEVER_STARTED
                                    )
                                    != TransferStatus.PAUSED
                                ):
                                    transfer_progress[temp_path][
                                        "status"
                                    ] = TransferStatus.DOWNLOADING
                                while True:
                                    if (
                                        transfer_progress[temp_path]["status"]
                                        == TransferStatus.PAUSED
                                    ):
                                        file_to_write.close()
                                        file_recv_socket.close()
                                        return f"Download for file {file_header['path']} was paused"
                                    file_bytes_read: bytes = sender.recv(FILE_BUFFER_LEN)
                                    if not offset:
                                        hash.update(file_bytes_read)
                                    num_bytes_read = len(file_bytes_read)
                                    byte_count += num_bytes_read
                                    transfer_progress[temp_path]["progress"] = byte_count
                                    file_to_write.write(file_bytes_read)
                                    progress_bar.update(num_bytes_read)
                                    # logging.debug(
                                    #     msg=f"Received chunk of size {num_bytes_read}, received {byte_count} of {file_header['size']}"
                                    # )
                                    if num_bytes_read == 0:
                                        break

                                hash_str = ""
                                if offset:
                                    file_to_write.seek(0)
                                    hash_str = get_file_hash(str(temp_path))
                                file_to_write.close()

                                received_hash = hash.hexdigest() if not offset else hash_str
                                if (request_hash and received_hash == file_header["hash"]) or (
                                    received_hash == file_requested["hash"]
                                ):
                                    transfer_progress[temp_path][
                                        "status"
                                    ] = TransferStatus.COMPLETED
                                    final_download_path.parent.mkdir(parents=True, exist_ok=True)
                                    shutil.move(temp_path, final_download_path)
                                    return "Succesfully received 1 file"
                                else:
                                    transfer_progress[temp_path] = TransferStatus.FAILED
                                    logging.error(
                                        msg=f"Failed integrity check for file {file_header['path']}"
                                    )
                                    return "Integrity check failed"
                            except Exception as e:
                                logging.error(e, exc_info=True)
                                return "File received but failed to save"
                        except Exception as e:
                            logging.error(e, exc_info=True)
                            return "Unable to write file"
                    else:
                        logging.error(
                            msg=f"Not enough space to receive file {file_header['path']}, {file_header['size']}"
                        )
                        return "Not enough space to receive file"
                else:
                    raise RequestException(
                        f"Sender sent invalid message type in header: {res_type}",
                        ExceptionCode.INVALID_HEADER,
                    )
            case HeaderCode.ERROR.value:
                res_len = int(client_peer_socket.recv(HEADER_MSG_LEN).decode(FMT).strip())
                res = client_peer_socket.recv(res_len)
                err: RequestException = msgpack.unpackb(
                    res,
                    object_hook=RequestException.from_dict,
                    raw=False,
                )
                raise err
            case _:
                err = RequestException(
                    f"Invalid message type in header: {res_type}",
                    ExceptionCode.INVALID_HEADER,
                )
                raise err
    except UnicodeDecodeError as e:
        logging.error(f"UnicodeDecodeError: {e}")
        raise RequestException("Invalid message type in header", ExceptionCode.INVALID_HEADER)
    except Exception as e:
        logging.error(e)
        raise e


def send_handler() -> None:
    global client_send_socket
    global transfer_progress
    # with StdoutProxy(sleep_between_writes=0):
    mode_prompt: PromptSession = PromptSession(
        "\nMODE: \n1. Browse files\n2. Send message\n3. Pause/resume downloads\n4. View online peers\n0. Exit\nEnter Mode: "
    )
    recipient_prompt: PromptSession = PromptSession("Enter username: ")
    while True:
        mode = mode_prompt.prompt()
        match mode:
            case "1":
                # search_term = search_prompt.prompt()
                # search_res_list = [
                #     r"(\S+)$",
                #     r"'(.+)'$",
                #     r'"(.+)"$',
                # ]

                # searchquery = ""
                # for r in search_res_list:
                #     match_res = re.match(r, search_term)
                #     if match_res:
                #         searchquery = match_res.group(1)
                #         break
                # if searchquery:
                # searchquery_bytes = searchquery.encode(FMT)
                searchquery_bytes = b" "
                search_header = f"{HeaderCode.FILE_BROWSE.value}{len(searchquery_bytes):<{HEADER_MSG_LEN}}".encode(
                    FMT
                )
                client_send_socket.send(search_header + searchquery_bytes)
                response_header_type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
                if response_header_type == HeaderCode.FILE_BROWSE.value:
                    response_len = int(client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip())
                    browse_files: list[DBData] = msgpack.unpackb(
                        recvall(client_send_socket, response_len),
                    )
                    # search_result = [
                    #     FileSearchResult(*result) for result in browse_files
                    # ]
                    if len(browse_files):
                        for index, data in enumerate(browse_files):
                            print(f"{index + 1}. {data['uname']}")

                        # for i, res in enumerate(search_result):
                        #     print(f"{i+1} PATH: {res.filepath} \n\t USER: {res.uname}")

                        uname_choice_prompt: PromptSession = PromptSession(
                            "Enter uname to browse: "
                        )
                        uname_choice: str = uname_choice_prompt.prompt()

                        if not uname_choice.isdigit() or not (
                            1 <= int(uname_choice) <= len(browse_files)
                        ):
                            continue
                        selected_user = browse_files[int(uname_choice) - 1]
                        files_requested = selected_user["share"]
                        print("\n" + selected_user["uname"] + "/share/")
                        display_share_dict(files_requested, 1)

                        file_choice_prompt: PromptSession = PromptSession(
                            "Enter filepath to download: "
                        )
                        file_choice: str = file_choice_prompt.prompt()
                        file_item = find_file(selected_user["share"], file_choice)

                        if file_item is None:
                            print("\nFile path not found")
                            continue

                        peer_ip = request_ip(selected_user["uname"], client_send_socket)

                        if peer_ip is not None:
                            executor = ThreadPoolExecutor(2)
                            if file_item["type"] == "file":
                                progress_bar = tqdm.tqdm(
                                    total=file_item["size"],
                                    desc=f"Downloading {file_item['name']}",
                                    unit="B",
                                    unit_scale=True,
                                    unit_divisor=1024,
                                    colour="green",
                                )
                                transfer_progress[
                                    TEMP_FOLDER_PATH / selected_user["uname"] / file_item["path"]
                                ] = {
                                    "progress": 0,
                                    "status": TransferStatus.NEVER_STARTED,
                                }
                                executor.submit(
                                    req_file_worker,
                                    file_item,
                                    selected_user["uname"],
                                    peer_ip,
                                    progress_bar,
                                )
                            else:
                                files_to_request: list[DirData] = []
                                get_files_in_dir(
                                    file_item["children"],
                                    files_to_request,
                                )
                                total_size = sum([file["size"] for file in files_to_request])
                                progress_bar = tqdm.tqdm(
                                    total=total_size,
                                    desc=f"Downloading {file_item['name']}",
                                    unit="B",
                                    unit_scale=True,
                                    unit_divisor=1024,
                                    colour="green",
                                )
                                for f in files_to_request:
                                    transfer_progress[
                                        TEMP_FOLDER_PATH / selected_user["uname"] / f["path"]
                                    ] = {
                                        "progress": 0,
                                        "status": TransferStatus.NEVER_STARTED,
                                    }
                                executor.map(
                                    req_file_worker,
                                    files_to_request,
                                    [selected_user["uname"]] * len(files_to_request),
                                    [peer_ip] * len(files_to_request),
                                    [progress_bar] * len(files_to_request),
                                )
                        else:
                            print(f"\nNo user found with username {selected_user['uname']}")
                    else:
                        print("\nNo results found")
                else:
                    logging.error("Error occured while searching for files")
            case "2":
                recipient = recipient_prompt.prompt()
                if recipient:
                    recipient = recipient.encode(FMT)
                    request_header = (
                        f"{HeaderCode.REQUEST_IP.value}{len(recipient):<{HEADER_MSG_LEN}}".encode(
                            FMT
                        )
                    )
                    logging.debug(msg=f"Sent packet {(request_header + recipient).decode(FMT)}")
                    client_send_socket.send(request_header + recipient)
                    res_type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
                    logging.debug(msg=f"Response type: {res_type}")
                    response_length = int(
                        client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip()
                    )
                    peer_ip = client_send_socket.recv(response_length)

                    if res_type == HeaderCode.REQUEST_IP.value:
                        recipient_addr: str = peer_ip.decode(FMT)
                        logging.debug(msg=f"Response: {recipient_addr}")
                        client_peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        client_peer_socket.connect((recipient_addr, CLIENT_RECV_PORT))
                        while True:
                            msg_prompt: PromptSession = PromptSession(
                                f"\nEnter message for {recipient.decode(FMT)}: ",
                                validator=MessageLenValidator(),
                            )
                            msg = msg_prompt.prompt()
                            if len(msg):
                                msg.strip().split()
                                send_res_list = [
                                    r"!send (\S+)$",
                                    r"!send '(.+)'$",
                                    r'!send "(.+)"$',
                                ]

                                filename = ""
                                for r in send_res_list:
                                    match_res = re.match(r, msg)
                                    if match_res:
                                        filename = match_res.group(1)
                                        break

                                if filename:
                                    filepath: Path = SHARE_FOLDER_PATH / filename
                                    logging.debug(f"{filepath} chosen to send")
                                    if filepath.exists() and filepath.is_file():
                                        filemetadata: FileMetadata = {
                                            "path": filename.split("/")[-1],
                                            "size": filepath.stat().st_size,
                                        }
                                        logging.debug(filemetadata)
                                        filemetadata_bytes = msgpack.packb(filemetadata)
                                        logging.debug(filemetadata_bytes)
                                        filesend_header = f"{HeaderCode.DIRECT_TRANSFER.value}{len(filemetadata_bytes):<{HEADER_MSG_LEN}}".encode(
                                            FMT
                                        )
                                        try:
                                            file_to_send = filepath.open(mode="rb")
                                            logging.debug(
                                                f"Sending file {filename} to {recipient.decode(FMT)}"
                                            )
                                            client_peer_socket.send(
                                                filesend_header + filemetadata_bytes
                                            )
                                            with tqdm.tqdm(
                                                total=filemetadata["size"],
                                                desc=f"Sending {str(filepath).removeprefix(str(SHARE_FOLDER_PATH) + '/')}",
                                                unit="B",
                                                unit_scale=True,
                                                unit_divisor=1024,
                                                colour="green",
                                            ) as progress:
                                                total_bytes_read = 0
                                                while total_bytes_read != filemetadata["size"]:
                                                    bytes_read = file_to_send.read(FILE_BUFFER_LEN)
                                                    client_peer_socket.sendall(bytes_read)
                                                    num_bytes = len(bytes_read)
                                                    total_bytes_read += num_bytes
                                                    progress.update(num_bytes)
                                                progress.close()
                                                print("\nFile Sent")
                                                file_to_send.close()
                                        except Exception as e:
                                            logging.error(f"File Sending failed: {e}")
                                    else:
                                        logging.error(f"{filepath} not found")
                                        print(
                                            f"\nUnable to perform send request, ensure that the file is available in {SHARE_FOLDER_PATH}"
                                        )
                                else:
                                    msg = msg.encode(FMT)
                                    if msg == b"!exit":
                                        break
                                    header = f"{HeaderCode.MESSAGE.value}{len(msg):<{HEADER_MSG_LEN}}".encode(
                                        FMT
                                    )
                                    client_peer_socket.send(header + msg)
                    elif res_type == HeaderCode.ERROR.value:
                        err: RequestException = msgpack.unpackb(
                            peer_ip,
                            object_hook=RequestException.from_dict,
                            raw=False,
                        )
                        logging.error(msg=err)
                    else:
                        logging.error(f"Invalid message type in header: {res_type}")
            case "3":
                logging.debug(transfer_progress)
                transfer_progress_prompt = PromptSession(
                    get_pending_downloads(transfer_progress)
                    + "\nEnter file path to toggle download status: "
                )
                relative_path: str = transfer_progress_prompt.prompt()
                if relative_path:
                    path = TEMP_FOLDER_PATH / relative_path
                    executor = ThreadPoolExecutor(2)
                    if path.is_file():
                        if path in transfer_progress:
                            if transfer_progress[path]["status"] in [
                                TransferStatus.DOWNLOADING,
                                TransferStatus.NEVER_STARTED,
                            ]:
                                transfer_progress[path]["status"] = TransferStatus.PAUSED
                                logging.debug(
                                    msg=f"{str(path)} -> {transfer_progress[path]['status']}"
                                )
                                print(f"{str(path)} -> {transfer_progress[path]['status']}")
                                print(f"\nPaused transfer for file {str(path)}")
                            elif transfer_progress[path]["status"] == TransferStatus.PAUSED:
                                uname = str(path).removeprefix(str(TEMP_FOLDER_PATH)).split("/")[1]
                                peer_ip = request_ip(uname, client_send_socket)
                                file_item: DirData = {
                                    "name": path.name,
                                    "path": relative_path.removeprefix(uname + "/"),
                                    "type": "file",
                                    "size": 0,
                                    "hash": None,
                                    "compression": CompressionMethod.NONE,
                                    "children": None,
                                }
                                if peer_ip is not None:
                                    executor = ThreadPoolExecutor(2)
                                    progress_bar = tqdm.tqdm(
                                        total=file_item["size"],
                                        desc=f"Downloading {file_item['name']}",
                                        unit="B",
                                        unit_scale=True,
                                        unit_divisor=1024,
                                        colour="green",
                                    )
                                    transfer_progress[path]["status"] = TransferStatus.DOWNLOADING
                                    executor.submit(
                                        req_file_worker, file_item, uname, peer_ip, progress_bar
                                    )
                                else:
                                    print(f"\nUser with username {uname} not found")
                            else:
                                print(f"\nDownload status for file {str(path)} cannot be changed")
                        else:
                            print("\nCould not retrieve file transfer status")
                    elif path.is_dir():
                        uname = str(path).removeprefix(str(TEMP_FOLDER_PATH)).split("/")[1]
                        peer_ip = request_ip(uname, client_send_socket)
                        if peer_ip is not None:
                            paused_dir_files: list[DirData] = []
                            for (
                                pathname,
                                progress,
                            ) in transfer_progress.items():
                                if path in pathname.parents:
                                    if progress["status"] == TransferStatus.PAUSED:
                                        transfer_progress[pathname][
                                            "status"
                                        ] = TransferStatus.DOWNLOADING
                                        paused_dir_files.append(
                                            {
                                                "name": pathname.name,
                                                "path": str(
                                                    pathname.relative_to(TEMP_FOLDER_PATH / uname)
                                                ),
                                                "type": "file",
                                                "size": 0,
                                                "hash": None,
                                                "compression": CompressionMethod.NONE,
                                                "children": None,
                                            }
                                        )
                                    elif progress["status"] in [
                                        TransferStatus.DOWNLOADING,
                                        TransferStatus.NEVER_STARTED,
                                    ]:
                                        transfer_progress[pathname][
                                            "status"
                                        ] = TransferStatus.PAUSED
                                        logging.debug(
                                            msg=f"{str(pathname)} -> {transfer_progress[pathname]['status']}"
                                        )
                                        print(
                                            f"{str(pathname)} -> {transfer_progress[pathname]['status']}"
                                        )
                                        print(f"\nPaused transfer for file {str(pathname)}")

                            total_size = sum([file["size"] for file in paused_dir_files])
                            progress_bar = tqdm.tqdm(
                                total=total_size,
                                desc=f"Downloading {path.name}",
                                unit="B",
                                unit_scale=True,
                                unit_divisor=1024,
                                colour="green",
                            )
                            executor.map(
                                req_file_worker,
                                paused_dir_files,
                                [uname] * len(paused_dir_files),
                                [peer_ip] * len(paused_dir_files),
                                [progress_bar] * len(paused_dir_files),
                            )
                    else:
                        print("\nFile does not exist")
            case "4":
                for uname, last_active in uname_to_status.items():
                    if time.time() - last_active <= ONLINE_TIMEOUT:
                        print(f"{uname}: Online")
                    else:
                        timestamp = time.localtime(last_active)
                        print(
                            f"{uname}: Offline (Last active : {time.strftime('%d-%m-%Y %H:%M:%S', timestamp)})"
                        )

            case "0":
                # if os.name == "nt":
                #     os._exit(0)
                # else:
                #     os.kill(os.getpid(), signal.SIGTERM)
                sys.exit(0)


def req_file_worker(file_item: DirData, uname: str, peer_ip: str, progress_bar: tqdm.tqdm):
    client_peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_peer_socket.connect((peer_ip, CLIENT_RECV_PORT))
    request_file(file_item, uname, client_peer_socket, progress_bar)


def send_file(
    filepath: Path,
    requester: tuple[str, int],
    request_hash: bool,
    resume_offset: int,
) -> None:
    file_send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    file_send_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    file_send_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 0)
    file_send_socket.connect(requester)
    hash = ""
    # compression = CompressionMethod.NONE

    # file_size = filepath.stat().st_size
    # if file_size < COMPRESSION_THRESHOLD:
    #     compression = CompressionMethod.ZSTD
    #     compressor = zstd.ZstdCompressor()
    #     with filepath.open(mode="rb") as uncompressed_file:
    #         with compressor.stream_writer(uncompressed_file) as writer:
    #             pass
    if request_hash:
        hash = get_file_hash(str(filepath))

    filemetadata: FileMetadata = {
        "path": str(filepath).removeprefix(str(SHARE_FOLDER_PATH) + "/"),
        "size": filepath.stat().st_size,
        "hash": hash if request_hash else None,
        # "compression": compression,
    }

    logging.debug(filemetadata)
    filemetadata_bytes = msgpack.packb(filemetadata)
    logging.debug(filemetadata_bytes)
    filesend_header = (
        f"{HeaderCode.DIRECT_TRANSFER.value}{len(filemetadata_bytes):<{HEADER_MSG_LEN}}".encode(FMT)
    )

    try:
        file_to_send = filepath.open(mode="rb")
        logging.debug(f"Sending file {filemetadata['path']} to {requester}")
        file_send_socket.send(filesend_header + filemetadata_bytes)
        with tqdm.tqdm(
            total=filemetadata["size"] - resume_offset,
            desc=f"Sending {str(filepath).removeprefix(str(SHARE_FOLDER_PATH) + '/')}",
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
            colour="green",
        ) as progress:
            total_bytes_read = 0
            file_to_send.seek(resume_offset)
            while total_bytes_read != filemetadata["size"] - resume_offset:
                time.sleep(0.05)
                bytes_read = file_to_send.read(FILE_BUFFER_LEN)
                num_bytes = file_send_socket.send(bytes_read)
                total_bytes_read += num_bytes
                progress.update(num_bytes)
                # logging.debug(
                #     f"Sent chunk of size {num_bytes}, total {total_bytes_read} of {filemetadata['size']}"
                # )
            progress.close()
            print("\nFile Sent")
            file_to_send.close()
            file_send_socket.close()
        if request_hash:
            update_hash_params: UpdateHashParams = {
                "filepath": str(filepath).removeprefix(str(SHARE_FOLDER_PATH) + "/"),
                "hash": hash,
            }
            update_hash_bytes = msgpack.packb(update_hash_params)
            update_hash_header = (
                f"{HeaderCode.UPDATE_HASH.value}{len(update_hash_bytes):<{HEADER_MSG_LEN}}".encode(
                    FMT
                )
            )
            client_send_socket.send(update_hash_header + update_hash_bytes)
    except Exception as e:
        logging.error(f"File Sending failed: {e}")
    # finally:
    #     concurrent_send_count -= 1


def receive_msg(socket: socket.socket) -> str:
    global client_send_socket
    logging.debug(f"Receiving from {socket.getpeername()}")
    message_type = socket.recv(HEADER_TYPE_LEN).decode(FMT)
    if not len(message_type):
        raise RequestException(
            msg=f"Peer at {socket.getpeername()} closed the connection",
            code=ExceptionCode.DISCONNECT,
        )
    elif message_type not in [
        HeaderCode.MESSAGE.value,
        HeaderCode.DIRECT_TRANSFER.value,
        HeaderCode.FILE_REQUEST.value,
    ]:
        raise RequestException(
            msg=f"Invalid message type in header. Received [{message_type}]",
            code=ExceptionCode.INVALID_HEADER,
        )
    else:
        match message_type:
            case HeaderCode.DIRECT_TRANSFER.value:
                file_header_len = int(socket.recv(HEADER_MSG_LEN).decode(FMT))
                file_header: FileMetadata = msgpack.unpackb(socket.recv(file_header_len))
                logging.debug(msg=f"receiving file with metadata {file_header}")
                write_path: Path = get_unique_filename(RECV_FOLDER_PATH / file_header["path"])
                try:
                    file_to_write = open(str(write_path), "wb")
                    logging.debug(f"Creating and writing to {write_path}")
                    try:
                        byte_count = 0
                        with tqdm.tqdm(
                            total=file_header["size"],
                            desc=f"Receiving {file_header['path']}",
                            unit="B",
                            unit_scale=True,
                            unit_divisor=1024,
                            colour="green",
                        ) as progress:
                            while byte_count != file_header["size"]:
                                file_bytes_read: bytes = socket.recv(FILE_BUFFER_LEN)
                                byte_count += len(file_bytes_read)
                                file_to_write.write(file_bytes_read)
                                progress.update(len(file_bytes_read))
                            file_to_write.close()
                            return "Succesfully received 1 file"
                    except Exception as e:
                        logging.error(e)
                        return "File received but failed to save"
                except Exception as e:
                    logging.error(e)
                    return "Unable to write file"
            case HeaderCode.FILE_REQUEST.value:
                req_header_len = int(socket.recv(HEADER_MSG_LEN).decode(FMT))
                file_req_header: FileRequest = msgpack.unpackb(socket.recv(req_header_len))
                logging.debug(msg=f"Received request: {file_req_header}")
                requested_file_path = SHARE_FOLDER_PATH / file_req_header["filepath"]
                if requested_file_path.is_file():
                    socket.send(HeaderCode.FILE_REQUEST.value.encode(FMT))
                    send_file_thread = threading.Thread(
                        target=send_file,
                        args=(
                            requested_file_path,
                            (socket.getpeername()[0], file_req_header["port"]),
                            file_req_header["request_hash"],
                            file_req_header["resume_offset"],
                        ),
                    )
                    send_file_thread.start()
                    return "File requested by user"
                elif requested_file_path.is_dir():
                    raise RequestException(
                        f"Requested a directory, {file_req_header['filepath']} is not a file.",
                        ExceptionCode.BAD_REQUEST,
                    )
                else:
                    share_data = msgpack.packb(path_to_dict(SHARE_FOLDER_PATH)["children"])
                    share_data_header = (
                        f"{HeaderCode.SHARE_DATA.value}{len(share_data):<{HEADER_MSG_LEN}}".encode(
                            FMT
                        )
                    )
                    client_send_socket.sendall(share_data_header + share_data)
                    raise RequestException(
                        f"Requested file {file_req_header['filepath']} is not available",
                        ExceptionCode.NOT_FOUND,
                    )
            case _:
                message_len = int(socket.recv(HEADER_MSG_LEN).decode(FMT))
                return recvall(socket, message_len).decode(FMT)


def receive_handler() -> None:
    global client_send_socket
    global client_recv_socket
    peers: dict[str, str] = {}

    while True:
        read_sockets: list[socket.socket]
        read_sockets, _, __ = select.select(connected, [], [], 1)
        for notified_socket in read_sockets:
            if notified_socket == client_recv_socket:
                peer_socket, peer_addr = client_recv_socket.accept()
                logging.debug(
                    msg=f"Accepted new connection from {peer_addr[0]}:{peer_addr[1]}",
                )
                try:
                    connected.append(peer_socket)
                    lookup = peer_addr[0].encode(FMT)
                    header = (
                        f"{HeaderCode.REQUEST_UNAME.value}{len(lookup):<{HEADER_MSG_LEN}}".encode(
                            FMT
                        )
                    )
                    logging.debug(msg=f"Sending packet {(header + lookup).decode(FMT)}")
                    client_send_socket.send(header + lookup)
                    res_type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
                    if res_type not in [
                        HeaderCode.REQUEST_UNAME.value,
                        HeaderCode.ERROR.value,
                    ]:
                        raise RequestException(
                            msg="Invalid message type in header",
                            code=ExceptionCode.INVALID_HEADER,
                        )
                    else:
                        response_length = int(
                            client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip()
                        )
                        response = client_send_socket.recv(response_length)
                        if res_type == HeaderCode.REQUEST_UNAME.value:
                            username = response.decode(FMT)
                            print(f"\nUser {username} is trying to send a message")
                            peers[peer_addr[0]] = username
                        else:
                            exception = msgpack.unpackb(
                                response,
                                object_hook=RequestException.from_dict,
                                raw=False,
                            )
                            logging.error(msg=exception)
                            raise exception
                except RequestException as e:
                    logging.error(msg=e)
                    break
            else:
                try:
                    msg: str = receive_msg(notified_socket)
                    username = peers[notified_socket.getpeername()[0]]
                    print(f"\n{username} > {msg}")
                except RequestException as e:
                    if e.code == ExceptionCode.DISCONNECT:
                        try:
                            connected.remove(notified_socket)
                        except ValueError:
                            logging.info("already removed")
                    logging.error(msg=f"Exception: {e.msg}")
                    break


def excepthook(args: threading.ExceptHookArgs) -> None:
    logging.fatal(msg=args)
    logging.fatal(msg=args.exc_traceback)


if __name__ == "__main__":
    with StdoutProxy(sleep_between_writes=0):
        try:
            while prompt_username() != HeaderCode.NEW_CONNECTION.value:
                error_len = int(client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip())
                error = client_send_socket.recv(error_len)
                exception: RequestException = msgpack.unpackb(
                    error, object_hook=RequestException.from_dict, raw=False
                )
                if exception.code == ExceptionCode.USER_EXISTS:
                    logging.error(msg=exception.msg)
                    print("\nSorry that username is taken, please choose another one")
                else:
                    logging.fatal(msg=exception.msg)
                    print("\nSorry something went wrong")
                    client_send_socket.close()
                    client_recv_socket.close()
                    sys.exit(1)
            print("\nSuccessfully registered")
            share_data = msgpack.packb(path_to_dict(SHARE_FOLDER_PATH)["children"])
            share_data_header = (
                f"{HeaderCode.SHARE_DATA.value}{len(share_data):<{HEADER_MSG_LEN}}".encode(FMT)
            )
            client_send_socket.sendall(share_data_header + share_data)
            try:
                with open(
                    f"/Drizzle/db/{my_username}_transfer_progress.obj", mode="rb"
                ) as transfer_dump:
                    transfer_dump.seek(0)
                    transfer_progress = pickle.load(transfer_dump)
                    logging.debug(
                        msg=f"Transfer Progress loaded from dump\n{pformat(transfer_progress)}"
                    )
            except Exception as e:
                # Fallback if no dump was created
                logging.error(msg=f"Failed to load transfer progress from dump: {e}")
                transfer_progress = generate_transfer_progress()
                logging.debug(msg=f"Transfer Progress generated\n{pformat(transfer_progress)}")
            threading.excepthook = excepthook
            send_thread = threading.Thread(target=send_handler)
            receive_thread = threading.Thread(target=receive_handler)
            heartbeat_thread = threading.Thread(target=send_heartbeat)
            send_thread.start()
            receive_thread.start()
            heartbeat_thread.start()
            send_thread.join()

        except (KeyboardInterrupt, EOFError, SystemExit):
            with open(
                f"/Drizzle/db/{my_username}_transfer_progress.obj", mode="wb"
            ) as transfer_dump:
                pickle.dump(transfer_progress, transfer_dump)
            sys.exit(0)
        except:
            logging.fatal(msg=sys.exc_info()[0], exc_info=True)
            sys.exit(1)
