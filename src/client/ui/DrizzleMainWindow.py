# Imports (standard libraries)
import hashlib
import logging
import os
import pickle
import select
import shutil
import socket
import sys
import time
from datetime import datetime
from io import BufferedReader
from pathlib import Path
from pprint import pformat
from typing import Any, TypedDict

# Imports (PyPI)
import msgpack
from notifypy import Notify
from PyQt5.QtCore import (
    QCoreApplication,
    QMetaObject,
    QMutex,
    QObject,
    QRect,
    QRunnable,
    QSize,
    Qt,
    QThread,
    QThreadPool,
    pyqtSignal,
)
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLayout,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpacerItem,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

# Imports (UI components)
from ui.ErrorDialog import Ui_ErrorDialog
from ui.FileInfoDialog import Ui_FileInfoDialog
from ui.FileProgressWidget import Ui_FileProgressWidget
from ui.FileSearchDialog import Ui_FileSearchDialog
from ui.SettingsDialog import Ui_SettingsDialog

# Imports (utilities)
sys.path.append("../")
# from client.app import MainWindow
from utils.constants import (
    CLIENT_RECV_PORT,
    CLIENT_SEND_PORT,
    DIRECT_TEMP_FOLDER_PATH,
    FILE_BUFFER_LEN,
    FMT,
    HEADER_MSG_LEN,
    HEADER_TYPE_LEN,
    HEARTBEAT_TIMER,
    LEADING_HTML,
    ONLINE_TIMEOUT,
    SERVER_RECV_PORT,
    TEMP_FOLDER_PATH,
    TRAILING_HTML,
)
from utils.exceptions import ExceptionCode, RequestException
from utils.helpers import (
    construct_message_html,
    convert_size,
    generate_transfer_progress,
    get_directory_size,
    get_file_hash,
    get_files_in_dir,
    get_unique_filename,
    import_file_to_share,
    path_to_dict,
)
from utils.socket_functions import get_self_ip, recvall, request_ip, request_uname, update_share_data
from utils.types import (
    CompressionMethod,
    DBData,
    DirData,
    FileMetadata,
    FileRequest,
    HeaderCode,
    ItemSearchResult,
    Message,
    ProgressBarData,
    TransferProgress,
    TransferStatus,
    UpdateHashParams,
    UserSettings,
)

# Global constants
SERVER_IP = ""
SERVER_ADDR = ()
CLIENT_IP = get_self_ip()

# Logging configuration
logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    level=logging.DEBUG,
    handlers=[
        logging.FileHandler(
            f"{str(Path.home())}/.Drizzle/logs/client_{datetime.now().strftime('%d-%m-%Y_%H-%M-%S')}.log"
        ),
        # logging.StreamHandler(sys.stdout),
    ],
)
# socket to connect to main server
client_send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# socket to receive new connections from peers
client_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Configuring socket options to reuse addresses and immediately transmit data
client_send_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
client_recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
client_send_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
client_recv_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
client_recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY, 0x06)
client_send_socket.setsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY, 0x06)

# Mark packets with TOS value of IPTOS_THROUGHPUT and IPTOS_LOWDELAY to optimize for throughput and low delay
client_recv_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0x10 | 0x08)
client_send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0x10 | 0x08)

# Binding sockets
client_send_socket.bind((CLIENT_IP, CLIENT_SEND_PORT))
client_recv_socket.bind((CLIENT_IP, CLIENT_RECV_PORT))

# Make client receive socket listen for new connections
client_recv_socket.listen(5)

# Global variables

# List of peer sockets connected to the clients
connected = [client_recv_socket]
# Mapping from username to last seen timestamp
uname_to_status: dict[str, float] = {}
# Mapping from username to list of messages
messages_store: dict[str, list[Message]] = {}
# Username selected by the user in the list
selected_uname: str = ""
# List of file items chosen by the user for downloading
selected_file_items: list[DirData] = []
# The user's own username
self_uname: str = ""
# Mapping from file path to download status and progress
transfer_progress: dict[Path, TransferProgress] = {}
# Mapping from file path to progress bar displaying its status
progress_widgets: dict[Path, Ui_FileProgressWidget] = {}
# The settings of the current session
user_settings: UserSettings = {}
# Cache to lookup username of a given IP
uname_to_ip: dict[str, str] = {}
# Cache to lookup IP of a given username
ip_to_uname: dict[str, str] = {}
# Whether or not an error dialog is already open on the screen currently
error_dialog_is_open = False
# A mutex to prevent race conditions while sending data to the server socket from different threads
server_socket_mutex = QMutex()


def show_error_dialog(error_msg: str, show_settings: bool = False) -> None:
    """Displays an error dialog with the given message

    Parameters
    ----------
    error_msg : str
        The error message to be displayed in the dialog
    show_settings : bool, optional
        A flag used to indicate whether or not to display the settings button (default is False)
    """

    global user_settings
    global error_dialog_is_open

    error_dialog = QDialog()
    error_dialog.ui = Ui_ErrorDialog(error_dialog, error_msg, user_settings if show_settings else None)

    # Don't display dialog if another dialog is already open
    if not error_dialog_is_open:
        error_dialog_is_open = True
        error_dialog.exec()
        error_dialog_is_open = False


# Directory progress information
class DirProgress(TypedDict):
    mutex: QMutex
    current: int
    total: int
    status: TransferStatus


# Mapping from directory path to cumulative download status and progress
dir_progress: dict[Path, DirProgress] = {}


class SaveProgressWorker(QObject):
    """A worker that periodically saves the download progress and statuses to a file

    Methods
    -------
    dump_progress_data()
        Stores the current download progress and statuses of all files and folders to a file
    run()
        Runs the dump_progress_data function every 10 seconds
    """

    def dump_progress_data(self) -> None:
        """Pickles the transfer_progress, dir_progress and progress_widgets dictionaries into 3 files"""
        global transfer_progress
        global dir_progress
        global progress_widgets

        for path in transfer_progress.keys():
            if transfer_progress[path]["status"] in [
                TransferStatus.DOWNLOADING,
                TransferStatus.NEVER_STARTED,
            ]:
                transfer_progress[path]["status"] = TransferStatus.PAUSED

        # Pickle the transfer_progress dictionary
        with (Path.home() / ".Drizzle/db/transfer_progress.pkl").open(mode="wb") as transfer_progress_dump:
            logging.debug(msg="Created transfer progress dump")
            pickle.dump(transfer_progress, transfer_progress_dump)

        # Pickle the dir_progress dictionary
        with (Path.home() / ".Drizzle/db/dir_progress.pkl").open(mode="wb") as dir_progress_dump:
            logging.debug(msg="Created dir progress dump")
            dir_progress_writeable: dict[Path, Any] = {}
            for path in dir_progress.keys():
                dir_progress[path]["mutex"].lock()
                dir_progress_writeable[path] = {
                    "current": dir_progress[path]["current"],
                    "total": dir_progress[path]["total"],
                    "status": dir_progress[path]["status"],
                }
                dir_progress[path]["mutex"].unlock()
            pickle.dump(dir_progress_writeable, dir_progress_dump)

        # Pickle the progress_widgets dictionary
        with (Path.home() / ".Drizzle/db/progress_widgets.pkl").open(mode="wb") as progress_widgets_dump:
            progress_widgets_writeable: dict[Path, ProgressBarData] = {}
            for path, widget in progress_widgets.items():
                progress_widgets_writeable[path] = {
                    "current": widget.ui.progressBar.value(),
                    "total": widget.ui.total,
                }
            pickle.dump(progress_widgets_writeable, progress_widgets_dump)

    def run(self):
        """Runs the dump_progress_data periodically"""
        global transfer_progress
        global dir_progress
        global progress_widgets

        # Save the progress data every 10 seconds
        while True:
            self.dump_progress_data()
            time.sleep(10)


class HeartbeatWorker(QObject):
    """A worker that periodically sends heartbeat messages to the server

    Attributes
    ----------
    update_status : pyqtSignal
        A signal that is emitted every time new status data is obtained from the server

    Methods
    -------
    run()
        Sends heartbeat messages to the server periodically, every HEARTBEAT_TIMER seconds
    """

    update_status = pyqtSignal(dict)

    def run(self):
        """Sends a heartbeat message to the server every HEARTBEAT_TIMER seconds and updates the statuses of all users"""
        global client_send_socket
        global server_socket_mutex

        # Encode and send the heartbeat message
        heartbeat = HeaderCode.HEARTBEAT_REQUEST.value.encode(FMT)
        while True:
            server_socket_mutex.lock()
            client_send_socket.send(heartbeat)
            type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
            if type == HeaderCode.HEARTBEAT_REQUEST.value:
                # Receive updated user statuses from the server and emit the update_status signal
                length = int(client_send_socket.recv((HEADER_MSG_LEN)).decode(FMT))
                new_status = msgpack.unpackb(client_send_socket.recv(length))
                server_socket_mutex.unlock()
                self.update_status.emit(new_status)
                time.sleep(HEARTBEAT_TIMER)
            else:
                server_socket_mutex.unlock()
                logging.error(
                    f"Server sent invalid message type in header: {type}",
                )
                sys.exit(
                    show_error_dialog(
                        "An error occurred while communicating with the server.\n\
                        Try reconnecting or check the server logs.",
                        True,
                    )
                )


class ReceiveDirectTransferWorker(QRunnable):
    """A worker that receives files sent via Direct Transfer from a peer

    Attributes
    ----------
    metadata : FileMetadata
        The metadata of the file to be downloaded
    sender : str
        The username of the sender
    file_receive_socket : socket.socket
        The socket on which to receive the file

    Methods
    -------
    run()
        Receives the file from the sender on the file_receive_socket socket
    """

    def __init__(self, metadata: FileMetadata, sender: str, file_receive_socket: socket.socket):
        super().__init__()
        logging.debug("file recv worker init")
        self.metadata = metadata
        self.sender = sender
        self.file_recv_socket = file_receive_socket
        self.signals = Signals()

    def run(self):
        """Receives the file with the given metadata from the sender on the file_receive_socket socket"""
        global user_settings
        global transfer_progress

        try:
            # Accept connection from the sender
            sender, _ = self.file_recv_socket.accept()
            # Temporary path to write the file to while the download is not complete
            temp_path: Path = DIRECT_TEMP_FOLDER_PATH / self.sender / self.metadata["path"]
            # Final download path in the user's download folder to move the file to after the download is complete
            final_download_path: Path = get_unique_filename(
                Path(user_settings["downloads_folder_path"]) / self.sender / self.metadata["path"],
            )
            temp_path.parent.mkdir(parents=True, exist_ok=True)
            final_download_path.parent.mkdir(parents=True, exist_ok=True)

            # Initialize transfer progress with default values
            transfer_progress[temp_path] = {
                "status": TransferStatus.DOWNLOADING,
                "progress": 0,
                "percent_progress": 0.0,
            }

            logging.debug(msg="Obtaining file")
            # Check if there is sufficient disk space available to receive the file
            if shutil.disk_usage(user_settings["downloads_folder_path"]).free > self.metadata["size"]:
                with temp_path.open(mode="wb") as file_to_write:
                    byte_count = 0
                    hash = hashlib.sha1()
                    self.signals.receiving_new_file.emit((temp_path, self.metadata["size"], False))
                    while True:
                        logging.debug(msg="Obtaining file chunk")

                        # Receive a file chunk
                        file_bytes_read: bytes = sender.recv(FILE_BUFFER_LEN)

                        # Update cumulative file hash
                        hash.update(file_bytes_read)
                        num_bytes_read = len(file_bytes_read)
                        byte_count += num_bytes_read
                        transfer_progress[temp_path]["progress"] = byte_count

                        # Write chunk to temp file
                        file_to_write.write(file_bytes_read)

                        # Emit a signal to update the progress bar
                        self.signals.file_progress_update.emit(temp_path)

                        # If there are no more chunks being sent, terminate the transfer
                        if num_bytes_read == 0:
                            break

                    received_hash = hash.hexdigest()
                    # Compare hash of received file with hash given in the metadata
                    if received_hash == self.metadata["hash"]:
                        transfer_progress[temp_path]["status"] = TransferStatus.COMPLETED
                        final_download_path.parent.mkdir(parents=True, exist_ok=True)

                        # Move the file to the final download path in the user's download folder
                        shutil.move(temp_path, final_download_path)
                        print("Succesfully received 1 file")

                        # Emit a signal to delete the progress bar
                        self.signals.file_download_complete.emit(temp_path)
                        del transfer_progress[temp_path]
                    else:
                        transfer_progress[temp_path]["status"] = TransferStatus.FAILED
                        logging.error(msg=f"Failed integrity check for file {self.metadata['path']}")
                        show_error_dialog(f"Failed integrity check for file {self.metadata['path']}.")
        except Exception as e:
            logging.exception(msg=f"Failed to receive file: {e}")
            show_error_dialog(f"Failed to receive file: {e}")
        finally:
            # Close the connection with the sender
            self.file_recv_socket.close()


class HandleFileRequestWorker(QRunnable):
    """A worker that handles incoming requests to download files from other peers

    Attributes
    ----------
    filepath : Path
        The path to the file to be downloaded
    requester : tuple[str, int]
        The address of the requester, specified of a tuple of IP address and port number
    request_hash : bool
        Whether or not to send the hash of the file to the peer and the server
    resume_offset : int
        Number of bytes of offset to send the file from

    Methods
    -------
    run()
        Sends the requested file at the filepath to the requester
    """

    def __init__(self, filepath: Path, requester: tuple[str, int], request_hash: bool, resume_offset: int):
        super().__init__()
        self.filepath = filepath
        self.requester = requester
        self.request_hash = request_hash
        self.resume_offset = resume_offset

    def run(self) -> None:
        """Send the file at filepath if it exists to the requester at the given address after opening a new port"""

        # Open a new socket for sending the file
        file_send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        file_send_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        file_send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0x10 | 0x08)
        file_send_socket.setsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY, 0x06)
        try:
            # Attempt to connect to the requester at the given address
            file_send_socket.connect(self.requester)
        except Exception as e:
            logging.exception(f"Exception when sending file: {e}")
            return
        try:
            hash = ""

            # If request_hash is set, compute the hash of the file before sending it
            if self.request_hash:
                hash = get_file_hash(str(self.filepath))

            # Create the file metadata, encode it and send it to the requester
            filemetadata: FileMetadata = {
                "path": str(self.filepath).removeprefix(user_settings["share_folder_path"] + "/"),
                "size": self.filepath.stat().st_size,
                "hash": hash if self.request_hash else None,
            }

            logging.debug(filemetadata)
            filemetadata_bytes = msgpack.packb(filemetadata)
            filesend_header = f"{HeaderCode.DIRECT_TRANSFER.value}{len(filemetadata_bytes):<{HEADER_MSG_LEN}}".encode(
                FMT
            )

            with self.filepath.open(mode="rb") as file_to_send:
                logging.debug(f"Sending file {filemetadata['path']} to {self.requester}")
                # Send the file metadata to the requester
                file_send_socket.send(filesend_header + filemetadata_bytes)

                total_bytes_read = 0

                if os.name == "posix":
                    # On Unix-like systems use the high-performance socket.sendfile function with the resume_offset
                    file_send_socket.sendfile(file_to_send, self.resume_offset)
                else:
                    # On other systems
                    # Seek to the point in the file after the resume_offset
                    file_to_send.seek(self.resume_offset)

                    # Send file chunks until the whole file is sent
                    while total_bytes_read != filemetadata["size"] - self.resume_offset:
                        bytes_read = file_to_send.read(FILE_BUFFER_LEN)
                        num_bytes = file_send_socket.send(bytes_read)
                        total_bytes_read += num_bytes
                print("\nFile Sent")
            if self.request_hash:
                # If the requester set the request_hash option, the server does not have the hash of the file
                # so send the updated hash to the server
                update_hash_params: UpdateHashParams = {
                    "filepath": str(self.filepath).removeprefix(user_settings["share_folder_path"] + "/"),
                    "hash": hash,
                }
                update_hash_bytes = msgpack.packb(update_hash_params)
                update_hash_header = f"{HeaderCode.UPDATE_HASH.value}{len(update_hash_bytes):<{HEADER_MSG_LEN}}".encode(
                    FMT
                )
                server_socket_mutex.lock()
                client_send_socket.send(update_hash_header + update_hash_bytes)
                server_socket_mutex.unlock()
        except Exception as e:
            logging.exception(f"File Sending failed: {e}")
            show_error_dialog(f"File Sending failed. {e}")
        finally:
            file_send_socket.close()


class ReceiveHandler(QObject):
    """A worker that handles incoming packets sent by connected peers

    Attributes
    ----------
    message_received : pyqtSignal
        A signal that is emitted every time a message is received from a peer
    file_incoming : pyqtSignal
        A signal that is emitted every time a file is being received from a peer
    send_file_pool : QThreadPool
        The global thread pool used to run SendFileWorker instances

    Methods
    -------
    receive_msg(socket: socket.socket)
        Handle receiving incoming file requests, messages and Direct Transfer requests
    run()
        Accept new incoming connections from peers and execute receive_msg for each peer
    """

    message_received = pyqtSignal(dict)
    file_incoming = pyqtSignal(tuple)
    send_file_pool = QThreadPool.globalInstance()

    def receive_msg(self, socket: socket.socket) -> str | None:
        """Receives incoming messages, file requests or Direct Transfer requests

        Parameters
        ----------
        socket : socket.socket
            The socket on which to receive the message

        Returns
        ----------
        str | None
            Returns the message received from the peer, or None in case of an exception

        Raises
        ----------
        RequestException
            In case of any exceptions that occur in receiving the message
        """

        global client_send_socket
        global user_settings

        # Receive message type
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
            HeaderCode.DIRECT_TRANSFER_REQUEST.value,
            HeaderCode.FILE_REQUEST.value,
        ]:
            raise RequestException(
                msg=f"Invalid message type in header. Received [{message_type}]",
                code=ExceptionCode.INVALID_HEADER,
            )
        else:
            match message_type:
                # Direct Transfer
                case HeaderCode.DIRECT_TRANSFER.value:
                    # Receive file metadata
                    file_header_len = int(socket.recv(HEADER_MSG_LEN).decode(FMT))
                    file_header: FileMetadata = msgpack.unpackb(socket.recv(file_header_len))
                    logging.debug(msg=f"receiving file with metadata {file_header}")

                    # Final path to store the file in
                    write_path: Path = get_unique_filename(
                        Path(user_settings["downloads_folder_path"]) / file_header["path"],
                    )
                    try:
                        file_to_write = open(str(write_path), "wb")
                        logging.debug(f"Creating and writing to {write_path}")
                        try:
                            byte_count = 0

                            # Keep receiving file chunks until the entire file is received
                            while byte_count != file_header["size"]:
                                file_bytes_read: bytes = socket.recv(FILE_BUFFER_LEN)
                                byte_count += len(file_bytes_read)
                                file_to_write.write(file_bytes_read)
                            file_to_write.close()
                            return f"Received file {write_path.name}"
                        except Exception as e:
                            logging.exception(e)
                            # TODO: add status bar message here, show error in progress bar
                            return None
                    except Exception as e:
                        logging.exception(e)
                        # TODO: add status bar message here, show error in progress bar
                        return None
                # Incoming file request
                case HeaderCode.FILE_REQUEST.value:
                    # Receive file request
                    req_header_len = int(socket.recv(HEADER_MSG_LEN).decode(FMT))
                    file_req_header: FileRequest = msgpack.unpackb(socket.recv(req_header_len))
                    logging.debug(msg=f"Received request: {file_req_header}")
                    requested_file_path = Path(user_settings["share_folder_path"]) / file_req_header["filepath"]

                    # Check if the requested file exists and is a file
                    if requested_file_path.is_file():
                        socket.send(HeaderCode.FILE_REQUEST.value.encode(FMT))

                        # Spawn new HandleFileRequestWorker worker to transmit the file
                        send_file_handler = HandleFileRequestWorker(
                            requested_file_path,
                            (socket.getpeername()[0], file_req_header["port"]),
                            file_req_header["request_hash"],
                            file_req_header["resume_offset"],
                        )
                        self.send_file_pool.start(send_file_handler, QThread.HighPriority)  # type: ignore
                        return None
                    # If the requested file exists and is a directory
                    elif requested_file_path.is_dir():
                        raise RequestException(
                            f"Requested a directory, {file_req_header['filepath']} is not a file.",
                            ExceptionCode.BAD_REQUEST,
                        )
                    # If the requested file does not exist
                    else:
                        # Update the share data on the server again with the latest information
                        share_data = msgpack.packb(
                            path_to_dict(
                                Path(user_settings["share_folder_path"]),
                                user_settings["share_folder_path"],
                            )["children"]
                        )
                        share_data_header = f"{HeaderCode.SHARE_DATA.value}{len(share_data):<{HEADER_MSG_LEN}}".encode(
                            FMT
                        )
                        server_socket_mutex.lock()
                        client_send_socket.sendall(share_data_header + share_data)
                        server_socket_mutex.unlock()
                        raise RequestException(
                            f"Requested file {file_req_header['filepath']} is not available",
                            ExceptionCode.NOT_FOUND,
                        )
                # Incoming Direct Transfer request
                case HeaderCode.DIRECT_TRANSFER_REQUEST.value:
                    metadata_len = int(socket.recv(HEADER_MSG_LEN).decode(FMT))
                    metadata: FileMetadata = msgpack.unpackb(socket.recv(metadata_len))
                    # Emit the file_incoming signal
                    self.file_incoming.emit((metadata, socket))
                    return None
                # Incoming message
                case _:
                    message_len = int(socket.recv(HEADER_MSG_LEN).decode(FMT))
                    # Return the received message
                    return recvall(socket, message_len).decode(FMT)

    def run(self):
        """Receives new connections and handles them"""

        global messages_store
        global client_send_socket
        global client_recv_socket
        global connected
        global server_socket_mutex

        while True:
            read_sockets: list[socket.socket]
            # Use the select system call to get a list of sockets that are ready for receiving
            read_sockets, _, __ = select.select(connected, [], [])
            for notified_socket in read_sockets:
                # New incoming connection
                if notified_socket == client_recv_socket:
                    # Accept the connection
                    peer_socket, peer_addr = client_recv_socket.accept()
                    logging.debug(
                        msg=f"Accepted new connection from {peer_addr[0]}:{peer_addr[1]}",
                    )
                    try:
                        # Lookup the username of the peer in the cache
                        if ip_to_uname.get(peer_addr[0]) is None:
                            # In case of a cache miss, lookup the username from the server
                            server_socket_mutex.lock()
                            peer_uname = request_uname(peer_addr[0], client_send_socket)
                            server_socket_mutex.unlock()
                            if peer_uname is not None:
                                # Cache the username for future use
                                ip_to_uname[peer_addr[0]] = peer_uname
                        # Add the socket to the list of connected peers
                        connected.append(peer_socket)
                    except Exception as e:
                        logging.exception(msg=e)
                        show_error_dialog("Error occured when obtaining peer data. {e}")
                        break
                else:
                    # Incoming packet from a connected peer
                    try:
                        # Lookup the username in the cache
                        username = ip_to_uname[notified_socket.getpeername()[0]]
                        # Handle the incoming packet
                        message_content: str = self.receive_msg(notified_socket)
                        # If receive_msg returns a string, it is a message to be displayed in the message area
                        if message_content:
                            message: Message = {"sender": username, "content": message_content}
                            # Check if desktop notifications are enabled in the settings
                            if user_settings["show_notifications"] and username != selected_uname:
                                # Fire a notification with the message as the payload
                                notif = Notify()
                                notif.application_name = "Drizzle"
                                notif.title = "Message"
                                notif.message = f"{username}: {message_content}"
                                notif.send()
                            # Store the message in the messages_store
                            messages_store.setdefault(username, []).append(message)
                            # Emit the message_received signal to update the message area
                            self.message_received.emit(message)
                    except RequestException as e:
                        # Remove disconnected peers from the list of connected peers
                        if e.code == ExceptionCode.DISCONNECT:
                            try:
                                connected.remove(notified_socket)
                            except ValueError:
                                logging.info("already removed")
                        logging.error(msg=f"Exception: {e.msg}")
                        # show_error_dialog(f"Error occurred when communicating with peer.\n{e.msg}")
                        break
                    except Exception as e:
                        logging.exception(f"Error communicating with peer: {e}")


class SendFileWorker(QObject):
    """A worker that sends files (for Direct Transfer) to peers

    Attributes
    ----------
    sending_file : pyqtSignal
        A signal that is emitted when the file is being sent
    completed : pyqtSignal
        A signal that is emitted when the file transfer is complete
    filepath : Path
        The path to the file to be sent

    Methods
    -------
    run()
        Sends the file at filepath to the selected peer
    """

    sending_file = pyqtSignal(dict)
    completed = pyqtSignal()

    def __init__(self, filepath: Path):
        global client_send_socket
        global server_socket_mutex
        super().__init__()

        self.filepath = filepath
        self.peer_ip = ""

        # Lookup the IP of the selected username in the cache
        if uname_to_ip.get(selected_uname) is None:
            # In case of a cache miss, request the IP from the server and store it in the cache
            server_socket_mutex.lock()
            self.peer_ip = request_ip(selected_uname, client_send_socket)
            server_socket_mutex.unlock()
            uname_to_ip[selected_uname] = self.peer_ip
        else:
            self.peer_ip = uname_to_ip[selected_uname]

        if self.peer_ip is not None:
            # Open a new socket to connect to the peer
            self.client_peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_peer_socket.connect((self.peer_ip, CLIENT_RECV_PORT))
            self.client_peer_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0x10 | 0x08)
            self.client_peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY, 0x06)

    def run(self):
        """Sends the file at filepath to the selected peer"""

        global self_uname
        # If the file at filepath exists and is a file
        if self.filepath and self.filepath.is_file():
            logging.debug(f"{self.filepath} chosen to send")
            filemetadata: FileMetadata = {
                "path": self.filepath.name,
                "size": self.filepath.stat().st_size,
                "hash": get_file_hash(str(self.filepath)),
            }
            logging.debug(filemetadata)
            filemetadata_bytes = msgpack.packb(filemetadata)
            logging.debug(filemetadata_bytes)
            filesend_header = f"{HeaderCode.DIRECT_TRANSFER_REQUEST.value}{len(filemetadata_bytes):<{HEADER_MSG_LEN}}"
            filesend_header = filesend_header.encode(FMT)

            # Open a new socket to transmit the file
            file_send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            file_send_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            file_send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0x10 | 0x08)
            file_send_socket.setsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY, 0x06)

            file_to_send: BufferedReader
            try:
                logging.debug(f"Sending file {self.filepath} to {selected_uname}")

                # Send the file metadata to the peer
                self.client_peer_socket.send(filesend_header + filemetadata_bytes)

                response_type = self.client_peer_socket.recv(HEADER_TYPE_LEN).decode(FMT)
                logging.debug(f"Received header {response_type}")
                if response_type == HeaderCode.DIRECT_TRANSFER_REQUEST.value:
                    response_len = int(self.client_peer_socket.recv(HEADER_MSG_LEN).decode(FMT).strip())
                    logging.debug(f"Received len {response_len}")
                    port = int(self.client_peer_socket.recv(response_len).decode(FMT))
                    logging.debug(f"Received port {port}")

                    # If the recipient acknowledges the transfer, a valid port is sent
                    if port != -1:
                        # Connect to the recipient on the given port
                        file_send_socket.connect((self.peer_ip, port))
                        with self.filepath.open(mode="rb") as file_to_send:
                            total_bytes_read = 0
                            msg = f"Sending file {str(self.filepath)}"
                            if messages_store.get(selected_uname) is not None:
                                messages_store[selected_uname].append({"sender": self_uname, "content": msg})
                            else:
                                messages_store[selected_uname] = [{"sender": self_uname, "content": msg}]

                            # Emit the sending_file signal
                            self.sending_file.emit({"sender": self_uname, "content": msg})
                            if os.name == "posix":
                                # On Unix-like systems use the high performance socket.sendfile method
                                file_send_socket.sendfile(file_to_send)
                            else:
                                # On other systems
                                # Send file chunks until the entire file is sent
                                while total_bytes_read != filemetadata["size"]:
                                    logging.debug(f'sending file bytes {total_bytes_read} of {filemetadata["size"]}')
                                    bytes_read = file_to_send.read(FILE_BUFFER_LEN)
                                    file_send_socket.sendall(bytes_read)
                                    num_bytes = len(bytes_read)
                                    total_bytes_read += num_bytes
                            print("\nFile Sent")
            except Exception as e:
                logging.exception(f"Direct transfer failed: {e}")
                show_error_dialog(f"Failed to send file. {e}")
            finally:
                file_send_socket.close()

        else:
            logging.error(f"{self.filepath} not found")
            show_error_dialog("Selected file does not exist.")
            print(
                f"\nUnable to perform send request\n\
                ensure that the file is available in {user_settings['share_folder_path']}"
            )
        # Emit the completed event
        self.completed.emit()


class Signals(QObject):
    """A class containing signals that are emitted for various events

    Attributes
    ----------
    start_download : pyqtSignal
        A signal that is emitted when a download starts from the search dialog, to create a progress bar
    receiving_new_file : pyqtSignal
        A signal that is emitted when the a new file download starts, to create a progress bar
    file_progress_update : pyqtSignal
        A signal that is emitted when a file transfer progress is updated, to update the progress bar
    dir_progress_update : pyqtSignal
        A signal that is emitted when a directory transfer progress is updated, to update the progress bar
    pause_download : pyqtSignal
        A signal that is emitted when a file or directory transfer is paused
    resume_download : pyqtSignal
        A signal that is emitted when a file or directory transfer is resumed
    file_download_complete : pyqtSignal
        A signal that is emitted when a file or directory transfer is completed
    """

    dir_progress_update = pyqtSignal(tuple)
    file_download_complete = pyqtSignal(Path)
    file_progress_update = pyqtSignal(Path)
    pause_download = pyqtSignal(Path)
    receiving_new_file = pyqtSignal(tuple)
    resume_download = pyqtSignal(Path)
    start_download = pyqtSignal(dict)


class RequestFileWorker(QRunnable):
    """A worker that requests files or directories to be downloaded from the selected peer

    Attributes
    ----------
    file_item : DirData
        The metadata of the file item to be requested
    peer_ip : str
        The IP of the sender to request the file from
    sender : str
        The username of the sender
    parent_dir : Path | None
        In case of a directory download, the path of the parent directory to which the file_item belongs

    Methods
    ----------
    run()
        Requests the file item from the sender
    """

    def __init__(self, file_item: DirData, peer_ip: str, sender: str, parent_dir: Path | None) -> None:
        super().__init__()
        self.file_item = file_item
        self.peer_ip = peer_ip
        self.sender = sender
        self.parent_dir = parent_dir
        self.signals = Signals()

        logging.debug(msg=f"Thread worker for requesting {sender}/{file_item['name']}")

    def run(self) -> None:
        """Requests the file_item from the sender at peer_ip

        Raises
        ----------
        RequestException
            In case of any errors that occur during the transfer
        """

        global transfer_progress
        global user_settings

        try:
            # Open a new socket to request the file and connect to the sender
            self.client_peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_peer_socket.connect((self.peer_ip, CLIENT_RECV_PORT))

            # Open a new socket to listen for the incoming file transfer from the sender
            file_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            file_recv_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            file_recv_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0x10 | 0x08)
            file_recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY, 0x06)

            file_recv_socket.bind((CLIENT_IP, 0))
            file_recv_socket.listen()

            # Get the port of the file receive socket to send to the sender
            file_recv_port = file_recv_socket.getsockname()[1]

            offset = 0
            temp_path = TEMP_FOLDER_PATH / self.sender / self.file_item["path"]
            logging.debug(f"Using temp path {str(temp_path)}")
            # Check if an incomplete download already exists at the temp path (in case of resuming downloads)
            if temp_path.exists():
                # If such a file exists, then request an offset of the number of bytes already downloaded
                offset = temp_path.stat().st_size

            logging.debug(f"Offset of {offset} bytes")

            # Optimization for small files
            # If a file can be transmitted in a single packet (<=16 kB) then don't request the hash
            is_tiny_file = self.file_item["size"] <= FILE_BUFFER_LEN

            # Don't request the hash if it is already available or is a small file
            request_hash = self.file_item["hash"] is None and not is_tiny_file
            file_request: FileRequest = {
                "port": file_recv_port,
                "filepath": self.file_item["path"],
                "request_hash": request_hash,
                "resume_offset": offset,
            }

            file_req_bytes = msgpack.packb(file_request)
            file_req_header = f"{HeaderCode.FILE_REQUEST.value}{len(file_req_bytes):<{HEADER_MSG_LEN}}".encode(FMT)

            # Send the file request to the sender
            self.client_peer_socket.send(file_req_header + file_req_bytes)
            res_type = self.client_peer_socket.recv(HEADER_TYPE_LEN).decode(FMT)
            logging.debug(f"received header type {res_type} from sender")
            match res_type:
                # If the sender has the file
                case HeaderCode.FILE_REQUEST.value:
                    # Accept the new connection from the sender on the file receive port
                    sender, _ = file_recv_socket.accept()
                    logging.debug(msg=f"Sender tried to connect: {sender.getpeername()}")
                    res_type = sender.recv(HEADER_TYPE_LEN).decode(FMT)
                    if res_type == HeaderCode.DIRECT_TRANSFER.value:
                        file_header_len = int(sender.recv(HEADER_MSG_LEN).decode(FMT))
                        file_header: FileMetadata = msgpack.unpackb(sender.recv(file_header_len))
                        logging.debug(msg=f"receiving file with metadata {file_header}")

                        # Check if sufficient free disk space is available to receive the file
                        if shutil.disk_usage(user_settings["downloads_folder_path"]).free > file_header["size"]:
                            # Final path in the user's download folder to move the file to after downloading
                            final_download_path: Path = get_unique_filename(
                                Path(user_settings["downloads_folder_path"]) / file_header["path"],
                            )
                            try:
                                temp_path.parent.mkdir(parents=True, exist_ok=True)
                                file_to_write = temp_path.open("ab")
                                logging.debug(f"Creating and writing to {temp_path}")
                                try:
                                    byte_count = 0
                                    hash = hashlib.sha1()
                                    # Initialize the transfer progress of the file item
                                    if transfer_progress.get(temp_path) is None:
                                        transfer_progress[temp_path] = {}

                                    # If the download is not paused, set the status to DOWNLOADING
                                    if (
                                        transfer_progress[temp_path].get("status", TransferStatus.NEVER_STARTED)
                                        != TransferStatus.PAUSED
                                    ):
                                        transfer_progress[temp_path]["status"] = TransferStatus.DOWNLOADING

                                    # If the offset was 0 (i.e. new download) or if a progress bar was not created
                                    # then emit the receiving_new_file signal to create a progress bar
                                    if offset == 0 or progress_widgets.get(temp_path) is None:
                                        if self.parent_dir is None:
                                            self.signals.receiving_new_file.emit((temp_path, file_header["size"], True))

                                    # Keep receiving file chunks until no more chunks are received
                                    # or if the transfer is paused
                                    while True:
                                        if transfer_progress[temp_path]["status"] == TransferStatus.PAUSED:
                                            # If the transfer is paused, close the file and socket
                                            file_to_write.close()
                                            file_recv_socket.close()
                                            return

                                        # Receive a file chunk
                                        file_bytes_read: bytes = sender.recv(FILE_BUFFER_LEN)

                                        # Compute the hash if it is a new download and if it is not a small file
                                        if not offset and not is_tiny_file:
                                            hash.update(file_bytes_read)

                                        num_bytes_read = len(file_bytes_read)
                                        byte_count += num_bytes_read

                                        # Update the file progress
                                        transfer_progress[temp_path]["progress"] = byte_count + offset

                                        file_to_write.write(file_bytes_read)

                                        # If it is a file download, emit the file_progress_update signal
                                        if self.parent_dir is None:
                                            self.signals.file_progress_update.emit(temp_path)

                                        # Otherwise, emit the dir_progress_update signal
                                        else:
                                            self.signals.dir_progress_update.emit((self.parent_dir, num_bytes_read))
                                        if num_bytes_read == 0:
                                            break

                                    hash_str = ""
                                    # If this download was resumed, compute the hash from the start of the file
                                    if offset:
                                        file_to_write.seek(0)
                                        hash_str = get_file_hash(str(temp_path))
                                    file_to_write.close()

                                    # Check if the hashes received from the server (or sender) match
                                    received_hash = hash.hexdigest() if not offset else hash_str
                                    if (
                                        is_tiny_file
                                        or (request_hash and received_hash == file_header["hash"])
                                        or (received_hash == self.file_item["hash"])
                                    ):
                                        # Change the status of this download to COMPLETED
                                        transfer_progress[temp_path]["status"] = TransferStatus.COMPLETED

                                        # Move the file into the user's download folder
                                        final_download_path.parent.mkdir(parents=True, exist_ok=True)
                                        shutil.move(temp_path, final_download_path)
                                        print("Succesfully received 1 file")

                                        # Emit the file_download_complete signal to delete the progress bar
                                        self.signals.file_download_complete.emit(temp_path)
                                        del transfer_progress[temp_path]
                                    else:
                                        transfer_progress[temp_path]["status"] = TransferStatus.FAILED
                                        logging.error(msg=f"Failed integrity check for file {file_header['path']}")
                                        show_error_dialog(
                                            f"Failed integrity check for\n\
                                            file {file_header['path']}. Try downloading it again."
                                        )
                                except Exception as e:
                                    logging.exception(e)
                                    show_error_dialog(f"File received but failed to save. {e}")
                            except Exception as e:
                                logging.exception(e)
                                show_error_dialog("Unable to write file. {e}")
                        else:
                            logging.error(
                                msg=f"Not enough space to receive file {file_header['path']}, {file_header['size']}"
                            )
                            show_error_dialog(
                                f"Insufficient storage. You need at\n\
                                least {convert_size(file_header['size'])} of space to receive {file_header['path']}.",
                                True,
                            )
                    else:
                        raise RequestException(
                            f"Sender sent invalid message type in header: {res_type}",
                            ExceptionCode.INVALID_HEADER,
                        )
                case HeaderCode.ERROR.value:
                    # Receive the exception from the sender and raise it
                    res_len = int(self.client_peer_socket.recv(HEADER_MSG_LEN).decode(FMT).strip())
                    res = self.client_peer_socket.recv(res_len)
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
        except Exception as e:
            logging.exception(e)
            show_error_dialog(f"Error occurred when requesting file. {e}")
        finally:
            # Close the socket
            self.client_peer_socket.close()


class Ui_DrizzleMainWindow(QWidget):
    """A worker that requests files or directories to be downloaded from the selected peer

    Attributes
    ----------
    MainWindow : MainWindow
        The application's main window instance

    Methods
    ----------
    dump_progress_data()
        Saves the progress data to disk when the application is closed
    send_message()
        Sends a message to the selected user
    closeEvent(event) (Overriden)
        Closes the heartbeat thread before exiting the application
    render_file_tree(share: list[DirData] | None, parent: QTreeWidgetItem)
        Populates the file tree widget with data of the share data file tree of the selected user
    on_file_item_selected()
        Updates the information label and download button with the selected file items
    download_files()
        Starts threads to download the selected files
    messages_controller(message: Message)
        Updates the message area with a new message
    render_messages(messages_list: list[Message])
        Renders all the messages in the message area
    update_online_status(new_status: dict[str, int])
        Updates the last seen statuses of users
    on_user_selection_changed()
        Updates the file tree and message area with the data of the new selected user
    setupUi(MainWindow: MainWindow)
        Sets up the initial UI, performs application initialization steps
    retranslateUi(MainWindow: MainWindow)
        Sets text on labels and buttons, sets options for components
    open_settings(MainWindow: MainWindow)
        Opens up the settings dialog
    open_file_info(MainWindow: MainWindow)
        Opens the file info dialog
    import_files()
        Opens the file picker to import files into the share folder
    import_folder()
        Opens the file picker to import folders into the share folder
    share_file()
        Opens the file picker to select files to send via Direct Transfer
    pause_download(path: Path)
        Pauses the download of a file
    resume_download(path: Path)
        Resumes the download of a file
    remove_progress_widget(path: Path)
        Remove the progress bar corresponding to a file download
    new_file_progress(data: tuple[Path, int])
        Create a new progress bar for a file download
    update_file_progress(path: Path)
        Updates the progress bar with the latest progress of the file download
    update_dir_progress(progress_data: tuple[Path, int])
        Updates the progress bar with the latest progress of the directory download
    direct_transfer_controller(data: tuple[FileMetadata, socket.socket])
        Opens a dialog asking the user to accept or reject an incoming Direct Transfer request
    direct_transfer_accept(metadata: FileMetadata, sender: str, peer_socket: socket.socket)
        Accepts the Direct Transfer request and opens a new socket to receive the file
    direct_transfer_reject(peer_socket: socket.socket)
        Rejects the Direct Transfer request
    open_global_search(MainWindow: MainWindow)
        Opens the file search dialog
    download_from_global_search(item: ItemSearchResult)
        Downloads the selected item from the search dialog
    """

    global client_send_socket
    global client_recv_socket
    global uname_to_status

    def __init__(self, MainWindow):
        self.MainWindow = MainWindow
        super(Ui_DrizzleMainWindow, self).__init__()
        try:
            global user_settings
            global dir_progress
            global transfer_progress
            global progress_widgets

            self.user_settings = MainWindow.user_settings
            self.signals = Signals()

            # Connect signals
            self.signals.pause_download.connect(self.pause_download)
            self.signals.resume_download.connect(self.resume_download)

            user_settings = MainWindow.user_settings
            try:
                # Load pickled transfer progress if it exists
                with (Path.home() / ".Drizzle/db/transfer_progress.pkl").open(mode="rb") as transfer_progress_dump:
                    transfer_progress_dump.seek(0)
                    transfer_progress = pickle.load(transfer_progress_dump)
            except Exception as e:
                # Generate the transfer progress if no pickle was created
                logging.error(msg=f"Failed to load transfer progress from dump: {e}")
                transfer_progress = generate_transfer_progress()
                logging.debug(msg=f"Transfer Progress generated\n{pformat(transfer_progress)}")
            try:
                # Load pickled dir_progress if it exists
                with (Path.home() / ".Drizzle/db/dir_progress.pkl").open(mode="rb") as dir_progress_dump:
                    dir_progress_dump.seek(0)
                    dir_progress_readable: dict[Path, DirProgress] = pickle.load(dir_progress_dump)
                    for path, data in dir_progress_readable.items():
                        dir_progress[path] = data
                        dir_progress[path]["mutex"] = QMutex()
                    logging.debug(msg=f"Dir progress loaded from dump\n{pformat(dir_progress)}")
            except Exception as e:
                # TODO: Generate transfer progress for directories
                logging.error(msg=f"Failed to load dir progress from dump: {e}")

            # Connect to the server given in the settings
            SERVER_IP = self.user_settings["server_ip"]
            SERVER_ADDR = (SERVER_IP, SERVER_RECV_PORT)
            client_send_socket.settimeout(10)
            client_send_socket.connect(SERVER_ADDR)
            client_send_socket.settimeout(None)

            # Attempt to register the chosen username
            self_uname = self.user_settings["uname"]
            username = self_uname.encode(FMT)
            username_header = f"{HeaderCode.NEW_CONNECTION.value}{len(username):<{HEADER_MSG_LEN}}".encode(FMT)
            client_send_socket.send(username_header + username)
            type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
            if type != HeaderCode.NEW_CONNECTION.value:
                # If the registration fails, receive the error
                error_len = int(client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip())
                error = client_send_socket.recv(error_len)
                exception: RequestException = msgpack.unpackb(error, object_hook=RequestException.from_dict, raw=False)
                if exception.code == ExceptionCode.USER_EXISTS:
                    logging.error(msg=exception.msg)
                    show_error_dialog("Sorry that username is taken, please choose another one", True)
                else:
                    logging.fatal(msg=exception.msg)
                    print("\nSorry something went wrong")
                    client_send_socket.close()
                    client_recv_socket.close()
                    MainWindow.close()

            # Send share data to the server
            update_share_data(Path(self.user_settings["share_folder_path"]), client_send_socket)

            # Spawn heartbeat worker in its own thread
            self.heartbeat_thread = QThread()
            self.heartbeat_worker = HeartbeatWorker()
            self.heartbeat_worker.moveToThread(self.heartbeat_thread)
            self.heartbeat_thread.started.connect(self.heartbeat_worker.run)
            self.heartbeat_worker.update_status.connect(self.update_online_status)
            self.heartbeat_thread.start(QThread.LowestPriority)  # type: ignore

            # self.save_progress_thread = QThread()
            # self.save_progress_worker = SaveProgressWorker()
            # self.save_progress_worker.moveToThread(self.save_progress_thread)
            # self.save_progress_thread.started.connect(self.save_progress_worker.run)
            # self.save_progress_thread.start(QThread.LowestPriority) # type: ignore

            self.receive_thread = QThread()
            self.receive_worker = ReceiveHandler()
            self.receive_worker.moveToThread(self.receive_thread)
            self.receive_thread.started.connect(self.receive_worker.run)  # type: ignore
            self.receive_worker.message_received.connect(self.messages_controller)
            self.receive_worker.file_incoming.connect(self.direct_transfer_controller)
            self.receive_thread.start(QThread.HighestPriority)  # type: ignore

        except Exception as e:
            logging.error(f"Could not connect to server: {e}")
            sys.exit(
                show_error_dialog(
                    f"Could not connect to server: {e}\n\
                    \nEnsure that the server is online and you have entered the correct server IP.",
                    True,
                )
            )

        self.setupUi(MainWindow)

        try:
            with (Path.home() / ".Drizzle/db/progress_widgets.pkl").open(mode="rb") as progress_widgets_dump:
                progress_widgets_dump.seek(0)
                progress_widgets_readable: dict[Path, ProgressBarData] = pickle.load(progress_widgets_dump)
                for path, data in progress_widgets_readable.items():
                    self.new_file_progress((path, data["total"], True))
                    progress_widgets[path].ui.update_progress(data["current"])
                    progress_widgets[path].ui.btn_Toggle.setText("▶")
                    progress_widgets[path].ui.paused = True
                logging.debug(msg=f"Progress widgets loaded from dump\n{pformat(progress_widgets)}")
        except Exception as e:
            # Fallback if no dump was created
            logging.error(msg=f"Failed to load progress widgets from dump: {e}")
            # TODO: Generate transfer progress for progress widgets

    def dump_progress_data(self) -> None:
        """A method used to save progress data to disk. Called externally by the close event of MainWindow."""

        worker = SaveProgressWorker()
        worker.dump_progress_data()

    def send_message(self) -> None:
        """Sends a message to the global selected user"""

        global client_send_socket
        global client_recv_socket
        global messages_store
        global server_socket_mutex
        global selected_uname

        if self.txtedit_MessageInput.toPlainText() == "":
            return

        # Acquire lock for server socket
        server_socket_mutex.lock()
        peer_ip = ""
        # Request peer ip from server if not cached
        if uname_to_ip.get(selected_uname) is None:
            peer_ip = request_ip(selected_uname, client_send_socket)
            uname_to_ip[selected_uname] = peer_ip  # Update cache
        # Use cached peer ip
        else:
            peer_ip = uname_to_ip[selected_uname]
        # Release server socket
        server_socket_mutex.unlock()
        if peer_ip is not None:
            # Send message to peer
            client_peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_peer_socket.connect((peer_ip, CLIENT_RECV_PORT))
            msg = self.txtedit_MessageInput.toPlainText()
            msg_bytes = msg.encode(FMT)
            header = f"{HeaderCode.MESSAGE.value}{len(msg_bytes):<{HEADER_MSG_LEN}}".encode(FMT)
            try:
                client_peer_socket.send(header + msg_bytes)
                # Update local messages store
                if messages_store.get(selected_uname) is not None:
                    messages_store[selected_uname].append({"sender": self_uname, "content": msg})
                else:
                    messages_store[selected_uname] = [{"sender": self_uname, "content": msg}]
                self.render_messages(messages_store[selected_uname])
            except Exception as e:
                logging.error(f"Failed to send message: {e}")
                show_error_dialog(f"Failed to send message. {e}")
            finally:
                self.txtedit_MessageInput.clear()
        else:
            logging.error(f"Could not find ip for user {selected_uname}")
            show_error_dialog(f"This user has gone offline or does not exist. Try again later")

    def closeEvent(self, event) -> None:
        """Closes the heartbeat thread before exiting the application"""

        self.heartbeat_thread.exit()
        return super().closeEvent(event)

    def render_file_tree(self, share: list[DirData] | None, parent: QTreeWidgetItem) -> None:
        """Recursively traverse a directory structure to render in a tree widget

        Parameters
        ----------
        share : list[DirData] | None
            Dictionary representing a directory structure. Holds None for leaf nodes (files).
        parent : QTreeWidgetItem
            Parent item widget in the rendered tree
        """

        if share is None:
            return

        # Create widget for each item in the current level of the file tree
        for item in share:
            if item["type"] == "file":
                file_item = QTreeWidgetItem(parent)
                file_item.setText(0, item["name"])
                file_item.setData(0, Qt.UserRole, item)  # type: ignore
            else:
                dir_item = QTreeWidgetItem(parent)
                dir_item.setText(0, item["name"] + "/")
                dir_item.setData(0, Qt.UserRole, item)  # type: ignore
                # Recursive call for immediate children
                self.render_file_tree(item["children"], dir_item)

    def on_file_item_selected(self) -> None:
        """Slot to perform actions when user selects a file.

        This method sets the value of the global selected_file_items object. It also selectively enables or disables the File Info button.
        """

        global selected_file_items

        selected_items = self.file_tree.selectedItems()
        selected_file_items = []
        # Create list of file items
        for item in selected_items:
            data: DirData = item.data(0, Qt.UserRole)  # type: ignore
            selected_file_items.append(data)
        # Enable info btn if 1 item is selected
        if len(selected_items) == 1:
            self.lbl_FileInfo.setText(selected_file_items[0]["name"])
            self.btn_FileInfo.setEnabled(True)
        # Disable info btn if 0 or multiple items are selected
        else:
            self.lbl_FileInfo.setText(f"{len(selected_items)} items selected")
            self.btn_FileInfo.setEnabled(False)

    def download_files(self) -> None:
        """Method to start downloads for the global selected file items."""

        global selected_uname
        global client_send_socket
        global transfer_progress
        global selected_file_items
        global server_socket_mutex
        global uname_to_ip

        # Thread pool instanced
        request_file_pool = QThreadPool.globalInstance()

        for selected_item in selected_file_items:
            # Prevent download of an item that is actively being downloaded
            print(selected_item["path"], transfer_progress.keys())
            if TEMP_FOLDER_PATH / selected_uname / selected_item["path"] in transfer_progress:
                show_error_dialog("This item is already being downloaded")
                continue
            server_socket_mutex.lock()
            peer_ip = ""
            # Use cache to obtain peer ip
            if uname_to_ip.get(selected_uname) is None:
                peer_ip = request_ip(selected_uname, client_send_socket)
                uname_to_ip[selected_uname] = peer_ip
            else:
                peer_ip = uname_to_ip[selected_uname]
            server_socket_mutex.unlock()
            if peer_ip is None:
                logging.error(f"Selected user {selected_uname} does not exist")
                show_error_dialog(f"Selected user {selected_uname} does not exist")
                return
            # New transfer progress entry added
            transfer_progress[TEMP_FOLDER_PATH / selected_uname / selected_item["path"]] = {
                "progress": 0,
                "status": TransferStatus.NEVER_STARTED,
            }
            # Start file download thread in pool
            if selected_item["type"] == "file":
                request_file_worker = RequestFileWorker(selected_item, peer_ip, selected_uname, None)
                request_file_worker.signals.receiving_new_file.connect(self.new_file_progress)
                request_file_worker.signals.file_progress_update.connect(self.update_file_progress)
                request_file_worker.signals.file_download_complete.connect(self.remove_progress_widget)
                request_file_pool.start(request_file_worker, QThread.TimeCriticalPriority)  # type: ignore
            # Start folder download threads in pool
            else:
                files_to_request: list[DirData] = []
                get_files_in_dir(
                    selected_item["children"],
                    files_to_request,
                )
                dir_path = TEMP_FOLDER_PATH / selected_uname / selected_item["path"]
                # New directory progress entry added
                dir_progress[dir_path] = {
                    "current": 0,
                    "total": get_directory_size(selected_item, 0, 0)[0],
                    "status": TransferStatus.DOWNLOADING,
                    "mutex": QMutex(),
                }
                self.new_file_progress((dir_path, dir_progress[dir_path]["total"], True))
                # Add transfer progress for all files in folder
                for f in files_to_request:
                    transfer_progress[TEMP_FOLDER_PATH / selected_uname / f["path"]] = {
                        "progress": 0,
                        "status": TransferStatus.NEVER_STARTED,
                    }
                # Start threads for all files in folder
                for file in files_to_request:
                    request_file_worker = RequestFileWorker(file, peer_ip, selected_uname, dir_path)
                    request_file_worker.signals.dir_progress_update.connect(self.update_dir_progress)
                    request_file_pool.start(request_file_worker, QThread.TimeCriticalPriority)  # type: ignore

    def messages_controller(self, message: Message) -> None:
        """Method to conditionally render chat messages.

        Only performs the render operation if the received message is from the actively selected user.

        Parameters
        ----------

        message : Message
            the latest received message object
        """

        global selected_uname
        global self_uname
        # Only start rendering if selected user is sender
        if message["sender"] == selected_uname:
            self.render_messages(messages_store.get(selected_uname, []))

    def render_messages(self, messages_list: list[Message] | None) -> None:
        """Performs the render operation for chat messages.

        Clears message area and replaces it with new html for the selected user's message history. Automatically scrolls down widget to new content.

        Parameters
        ----------
        messages_list : list[Message]
            list of message objects to be displayed, in order.
        """

        global self_uname
        if messages_list is None or messages_list == []:
            self.txtedit_MessagesArea.clear()
            return
        # Construct message area html
        messages_html = LEADING_HTML
        for message in messages_list:
            messages_html += construct_message_html(message, message["sender"] == self_uname)
        messages_html += TRAILING_HTML
        self.txtedit_MessagesArea.setHtml(messages_html)
        # Scroll to latest
        self.txtedit_MessagesArea.verticalScrollBar().setValue(self.txtedit_MessagesArea.verticalScrollBar().maximum())

    def update_online_status(self, new_status: dict[str, float]) -> None:
        """Slot function that updates status display for users on the network.

        Called by the update_status signal.

        Parameters
        ----------
        new_status : dict[str, int]
            latest fetched status dictionary that maps username to a last active timestamp.
        """

        global uname_to_status
        # Existing users in local list
        old_users = set(uname_to_status.keys())
        # Users not initially in local list
        new_users = set(new_status.keys())
        # List of users to add
        to_add = new_users.difference(old_users)
        # List of users to remove
        users_to_remove = old_users.difference(new_users)

        # Update or remove widgets for users already present in local list
        for index in range(self.lw_OnlineStatus.count()):
            item = self.lw_OnlineStatus.item(index)
            username = item.data(Qt.UserRole)  # type: ignore
            if username in users_to_remove:
                item.setIcon(self.icon_Offline)
                timestamp = time.localtime(uname_to_status[username])
                item.setText(username + (f" (last active: {time.strftime('%d-%m-%Y %H:%M:%S', timestamp)})"))
            else:
                item.setIcon(
                    self.icon_Online if time.time() - new_status[username] <= ONLINE_TIMEOUT else self.icon_Offline
                )
                timestamp = time.localtime(new_status[username])
                item.setText(
                    username
                    + (
                        ""
                        if time.time() - new_status[username] <= ONLINE_TIMEOUT
                        else f" (last active: {time.strftime('%d-%m-%Y %H:%M:%S', timestamp)})"
                    )
                )
        # Add widgets for new users
        for uname in to_add:
            status_item = QListWidgetItem(self.lw_OnlineStatus)
            status_item.setIcon(
                self.icon_Online if time.time() - new_status[uname] <= ONLINE_TIMEOUT else self.icon_Offline
            )
            timestamp = time.localtime(new_status[uname])
            status_item.setData(Qt.UserRole, uname)  # type: ignore
            status_item.setText(
                uname + ""
                if time.time() - new_status[uname] <= ONLINE_TIMEOUT
                else f" (last active: {time.strftime('%d-%m-%Y %H:%M:%S', timestamp)})"
            )
        uname_to_status = new_status

    def on_user_selection_changed(self) -> None:
        """Slot function to perform actions when a different user is selected.

        This method is responsible for setting the global selected_user value and fetching a share directory structure to be rendered.
        It also conditionally enables buttons for sending messages and files.

        Called by the itemSelectionChanged signal as well as the refresh button's clicked signal.
        """

        global selected_uname
        global server_socket_mutex

        items = self.lw_OnlineStatus.selectedItems()
        if len(items):
            item = items[0]
            username: str = item.data(Qt.UserRole)  # type: ignore
            selected_uname = username
            self.render_messages(messages_store.get(selected_uname, []))
            # User considered offline if inactive beyond treshold [ONLINE_TIMEOUT] value
            enable_if_online = True if time.time() - uname_to_status[username] < ONLINE_TIMEOUT else False
            self.btn_SendMessage.setEnabled(enable_if_online)
            self.btn_SendFile.setEnabled(enable_if_online)
            self.btn_RefreshFileTree.setEnabled(enable_if_online)
            # Clear file tree if selected user is offline
            if time.time() - uname_to_status[username] > ONLINE_TIMEOUT:
                self.file_tree.clear()
                self.file_tree.headerItem().setText(0, "Selected user is offline")
                return
            # Fetch share data from server if selected user is online
            searchquery_bytes = username.encode(FMT)
            search_header = f"{HeaderCode.FILE_BROWSE.value}{len(searchquery_bytes):<{HEADER_MSG_LEN}}".encode(FMT)
            server_socket_mutex.lock()
            client_send_socket.send(search_header + searchquery_bytes)
            response_header_type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
            if response_header_type == HeaderCode.FILE_BROWSE.value:
                response_len = int(client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip())
                browse_files: list[DBData] = msgpack.unpackb(
                    recvall(client_send_socket, response_len),
                )
                server_socket_mutex.unlock()
                # Display share data for selected user
                if len(browse_files):
                    self.file_tree.clear()
                    self.file_tree.headerItem().setText(0, username)
                    self.render_file_tree(browse_files[0]["share"], self.file_tree)
                else:
                    print("No files found")
            else:
                server_socket_mutex.unlock()
                logging.error(f"Error occured while fetching files data, {response_header_type}")
                show_error_dialog(f"Error occured while fetching files data")
        # Clear file tree and disable buttons if no user selected
        else:
            self.btn_SendMessage.setEnabled(False)
            self.btn_SendFile.setEnabled(False)
            self.btn_RefreshFileTree.setEnabled(False)
            self.file_tree.clear()
            self.file_tree.headerItem().setText(0, "No user selected")

    def setupUi(self, MainWindow) -> None:
        """Method to perform UI initialisation.

        Sets layouts, widgets, items and properties in the MainWindow's ui.
        Majority code generated by the Qt UIC

        Parameters
        ----------
        MainWindow : MainWindow
            Instance of the application's main window.
        """

        if not MainWindow.objectName():
            MainWindow.setObjectName("MainWindow")
        MainWindow.resize(881, 744)
        sizePolicy = QSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(MainWindow.sizePolicy().hasHeightForWidth())
        MainWindow.setSizePolicy(sizePolicy)
        MainWindow.setUnifiedTitleAndToolBarOnMac(False)
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout_4 = QVBoxLayout(self.centralwidget)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.verticalLayout = QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.verticalLayout.setSizeConstraint(QLayout.SetMaximumSize)  # type: ignore
        self.verticalLayout.setContentsMargins(10, 0, 10, -1)
        self.Buttons = QHBoxLayout()
        self.Buttons.setSpacing(6)
        self.Buttons.setObjectName("Buttons")
        self.Buttons.setSizeConstraint(QLayout.SetDefaultConstraint)  # type: ignore
        self.label_3 = QLabel(self.centralwidget)
        self.label_3.setObjectName("label_3")
        sizePolicy1 = QSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        sizePolicy1.setHorizontalStretch(0)
        sizePolicy1.setVerticalStretch(0)
        sizePolicy1.setHeightForWidth(self.label_3.sizePolicy().hasHeightForWidth())
        self.label_3.setSizePolicy(sizePolicy1)
        font = QFont()
        font.setPointSize(14)
        font.setBold(True)
        font.setWeight(75)
        self.label_3.setFont(font)
        self.label_3.setMargin(0)

        self.Buttons.addWidget(self.label_3)

        self.horizontalSpacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.Buttons.addItem(self.horizontalSpacer)

        self.btn_GlobalSearch = QPushButton(self.centralwidget)
        self.btn_GlobalSearch.setObjectName("pushButton_7")

        self.btn_AddFiles = QPushButton(self.centralwidget)
        self.btn_AddFiles.setObjectName("pushButton_2")
        self.btn_AddFiles.clicked.connect(self.import_files)  # type: ignore

        self.btn_AddFolder = QPushButton(self.centralwidget)
        self.btn_AddFolder.setObjectName("pushButton_2")
        self.btn_AddFolder.clicked.connect(self.import_folder)  # type: ignore

        self.Buttons.addWidget(self.btn_GlobalSearch)
        self.Buttons.addWidget(self.btn_AddFiles)
        self.Buttons.addWidget(self.btn_AddFolder)

        self.btn_Settings = QPushButton(self.centralwidget)
        self.btn_Settings.setObjectName("pushButton")

        self.Buttons.addWidget(self.btn_Settings)

        self.verticalLayout.addLayout(self.Buttons)

        self.Content = QHBoxLayout()
        self.Content.setObjectName("Content")
        self.Files = QVBoxLayout()
        self.Files.setObjectName("Files")

        self.hl_BrowseFilesHeader = QHBoxLayout()

        self.label_BrowseFiles = QLabel(self.centralwidget)
        self.label_BrowseFiles.setObjectName("label")

        self.btn_RefreshFileTree = QPushButton(self.centralwidget)
        sizePolicy_RefreshBtn = QSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        sizePolicy_RefreshBtn.setHorizontalStretch(0)
        sizePolicy_RefreshBtn.setVerticalStretch(0)
        self.btn_RefreshFileTree.setSizePolicy(sizePolicy_RefreshBtn)
        self.btn_RefreshFileTree.setMinimumSize(QSize(30, 30))
        self.btn_RefreshFileTree.setMaximumSize(QSize(30, 30))
        self.btn_RefreshFileTree.setEnabled(False)
        self.btn_RefreshFileTree.clicked.connect(self.on_user_selection_changed)  # type: ignore

        self.hl_BrowseFilesHeader.addWidget(self.label_BrowseFiles)
        self.hl_BrowseFilesHeader.addWidget(self.btn_RefreshFileTree)
        self.hl_BrowseFilesHeader.addItem(self.horizontalSpacer)

        self.Files.addLayout(self.hl_BrowseFilesHeader)

        self.file_tree = QTreeWidget(self.centralwidget)
        # self.file_tree.itemClicked.connect(self.on_file_item_selected)
        self.file_tree.itemSelectionChanged.connect(self.on_file_item_selected)  # type: ignore
        self.file_tree.header().setVisible(True)
        self.file_tree.headerItem().setText(0, "No user selected")
        self.file_tree.setSelectionMode(QAbstractItemView.ExtendedSelection)

        self.Files.addWidget(self.file_tree)

        self.horizontalLayout_2 = QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.lbl_FileInfo = QLabel(self.centralwidget)
        self.lbl_FileInfo.setObjectName("label_4")

        self.horizontalLayout_2.addWidget(self.lbl_FileInfo)

        self.horizontalSpacer_2 = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.horizontalLayout_2.addItem(self.horizontalSpacer_2)

        self.btn_FileInfo = QPushButton(self.centralwidget)
        self.btn_FileInfo.setObjectName("pushButton_5")
        self.btn_FileInfo.setEnabled(True)
        self.btn_FileInfo.clicked.connect(lambda: self.open_file_info(MainWindow))  # type: ignore

        self.horizontalLayout_2.addWidget(self.btn_FileInfo)

        self.btn_FileDownload = QPushButton(self.centralwidget)
        self.btn_FileDownload.setObjectName("pushButton_4")
        self.btn_FileDownload.setEnabled(True)
        self.btn_FileDownload.clicked.connect(self.download_files)  # type: ignore

        self.horizontalLayout_2.addWidget(self.btn_FileDownload)

        self.Files.addLayout(self.horizontalLayout_2)

        self.Files.setStretch(1, 2)

        self.Content.addLayout(self.Files)

        self.Users = QVBoxLayout()
        self.Users.setObjectName("Users")
        self.Users.setSizeConstraint(QLayout.SetDefaultConstraint)  # type: ignore
        self.label_2 = QLabel(self.centralwidget)
        self.label_2.setObjectName("label_2")

        self.Users.addWidget(self.label_2)

        self.lw_OnlineStatus = QListWidget(self.centralwidget)
        self.lw_OnlineStatus.setSelectionMode(QAbstractItemView.SingleSelection)
        self.lw_OnlineStatus.itemSelectionChanged.connect(self.on_user_selection_changed)  # type: ignore
        self.icon_Online = QIcon()
        self.icon_Online.addFile("client/ui/res/earth.png", QSize(), QIcon.Normal, QIcon.Off)  # type: ignore

        self.icon_Offline = QIcon()
        self.icon_Offline.addFile("client/ui/web-off.png", QSize(), QIcon.Normal, QIcon.Off)  # type: ignore

        self.lw_OnlineStatus.setObjectName("listWidget")
        self.lw_OnlineStatus.setSortingEnabled(False)

        self.Users.addWidget(self.lw_OnlineStatus)

        self.txtedit_MessagesArea = QTextEdit(self.centralwidget)
        self.txtedit_MessagesArea.setObjectName("textEdit")
        sizePolicy2 = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        sizePolicy2.setHorizontalStretch(0)
        sizePolicy2.setVerticalStretch(5)
        sizePolicy2.setHeightForWidth(self.txtedit_MessagesArea.sizePolicy().hasHeightForWidth())
        self.txtedit_MessagesArea.setSizePolicy(sizePolicy2)
        self.txtedit_MessagesArea.setMinimumSize(QSize(0, 0))
        self.txtedit_MessagesArea.setTextInteractionFlags(Qt.TextSelectableByMouse)  # type: ignore

        self.Users.addWidget(self.txtedit_MessagesArea)

        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.horizontalLayout.setSizeConstraint(QLayout.SetDefaultConstraint)  # type: ignore

        self.txtedit_MessageInput = QPlainTextEdit(self.centralwidget)
        self.txtedit_MessageInput.setObjectName("plainTextEdit")
        self.txtedit_MessageInput.setEnabled(True)
        sizePolicy3 = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        sizePolicy3.setHorizontalStretch(0)
        sizePolicy3.setVerticalStretch(0)
        sizePolicy3.setHeightForWidth(self.txtedit_MessageInput.sizePolicy().hasHeightForWidth())
        self.txtedit_MessageInput.setSizePolicy(sizePolicy3)
        # Use smaller text area for OS-X to correctly theme corresponding buttons
        if sys.platform == "darwin":
            self.txtedit_MessageInput.setMaximumSize(QSize(16777215, 60))
        else:
            self.txtedit_MessageInput.setMaximumSize(QSize(16777215, 80))

        self.horizontalLayout.addWidget(self.txtedit_MessageInput)

        self.verticalLayout_6 = QVBoxLayout()
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.btn_SendMessage = QPushButton(self.centralwidget)
        self.btn_SendMessage.setObjectName("pushButton_3")
        self.btn_SendMessage.setEnabled(False)
        sizePolicy4 = QSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)
        sizePolicy4.setHorizontalStretch(0)
        sizePolicy4.setVerticalStretch(0)
        sizePolicy4.setHeightForWidth(self.btn_SendMessage.sizePolicy().hasHeightForWidth())
        self.btn_SendMessage.setSizePolicy(sizePolicy4)
        self.btn_SendMessage.clicked.connect(self.send_message)  # type: ignore

        self.verticalLayout_6.addWidget(self.btn_SendMessage)

        self.btn_SendFile = QPushButton(self.centralwidget)
        self.btn_SendFile.setObjectName("pushButton_6")
        sizePolicy4.setHeightForWidth(self.btn_SendFile.sizePolicy().hasHeightForWidth())
        self.btn_SendFile.setSizePolicy(sizePolicy4)
        self.btn_SendFile.setEnabled(False)
        self.btn_SendFile.clicked.connect(self.share_file)  # type: ignore

        self.verticalLayout_6.addWidget(self.btn_SendFile)

        self.horizontalLayout.addLayout(self.verticalLayout_6)

        self.Users.addLayout(self.horizontalLayout)

        self.Users.setStretch(1, 4)
        self.Users.setStretch(3, 1)

        self.Content.addLayout(self.Users)

        self.Content.setStretch(0, 3)
        self.Content.setStretch(1, 2)

        self.verticalLayout.addLayout(self.Content)

        self.label_12 = QLabel(self.centralwidget)
        self.label_12.setObjectName("label_12")

        self.verticalLayout.addWidget(self.label_12)

        self.scroll_FileProgress = QScrollArea(self.centralwidget)
        self.scroll_FileProgress.setObjectName("scrollArea")
        sizePolicy5 = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.MinimumExpanding)
        sizePolicy5.setHorizontalStretch(0)
        sizePolicy5.setVerticalStretch(0)
        sizePolicy5.setHeightForWidth(self.scroll_FileProgress.sizePolicy().hasHeightForWidth())
        self.scroll_FileProgress.setSizePolicy(sizePolicy5)
        # self.scroll_FileProgress.setMaximumSize(QSize(16777215, 250))
        self.scroll_FileProgress.setMinimumSize(QSize(0, 150))
        self.scroll_FileProgress.setWidgetResizable(True)
        self.scrollContents_FileProgress = QWidget()
        self.scrollContents_FileProgress.setObjectName("scrollAreaWidgetContents")
        self.scrollContents_FileProgress.setGeometry(QRect(0, 0, 831, 328))
        self.vBoxLayout_ScrollContents = QVBoxLayout(self.scrollContents_FileProgress)
        self.vBoxLayout_ScrollContents.setObjectName("verticalLayout_5")
        self.vBoxLayout_ScrollContents.setAlignment(Qt.AlignTop)  # type: ignore

        self.scroll_FileProgress.setWidget(self.scrollContents_FileProgress)

        self.verticalLayout.addWidget(self.scroll_FileProgress)

        self.verticalLayout_4.addLayout(self.verticalLayout)

        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)

        QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow) -> None:
        """Method to show initial content on the UI.

        Sets base text on labels and buttons.
        Majority code generated by the Qt UIC

        Parameters
        ----------
        MainWindow : MainWindow
            Instance of the application's main window.
        """

        MainWindow.setWindowTitle(QCoreApplication.translate("MainWindow", "Drizzle", None))
        self.label_3.setText(QCoreApplication.translate("MainWindow", f"Drizzle / {self.user_settings['uname']}", None))
        self.btn_GlobalSearch.setText(QCoreApplication.translate("MainWindow", "Global Search", None))
        self.btn_AddFiles.setText(QCoreApplication.translate("MainWindow", "Import Files", None))
        self.btn_AddFolder.setText(QCoreApplication.translate("MainWindow", "Import Folder", None))
        self.btn_Settings.setText(QCoreApplication.translate("MainWindow", "Settings", None))
        self.label_BrowseFiles.setText(QCoreApplication.translate("MainWindow", "Browse Files", None))

        self.btn_GlobalSearch.clicked.connect(lambda: self.open_global_search(MainWindow))  # type: ignore
        self.btn_Settings.clicked.connect(lambda: self.open_settings(MainWindow))  # type: ignore

        __sortingEnabled = self.file_tree.isSortingEnabled()
        self.file_tree.setSortingEnabled(__sortingEnabled)

        self.lbl_FileInfo.setText(QCoreApplication.translate("MainWindow", "No file or folder selected", None))
        self.btn_FileInfo.setText(QCoreApplication.translate("MainWindow", "Info", None))
        self.btn_FileDownload.setText(QCoreApplication.translate("MainWindow", "Download", None))
        self.label_2.setText(QCoreApplication.translate("MainWindow", "Users", None))

        __sortingEnabled1 = self.lw_OnlineStatus.isSortingEnabled()
        self.lw_OnlineStatus.setSortingEnabled(False)
        self.lw_OnlineStatus.setSortingEnabled(__sortingEnabled1)

        self.txtedit_MessageInput.setPlaceholderText(QCoreApplication.translate("MainWindow", "Enter message", None))
        self.btn_SendMessage.setText(QCoreApplication.translate("MainWindow", "Send Message", None))
        self.btn_SendFile.setText(QCoreApplication.translate("MainWindow", "Send File", None))
        self.label_12.setText(QCoreApplication.translate("MainWindow", "Downloading:", None))
        self.btn_RefreshFileTree.setText(QCoreApplication.translate("MainWindow", "⟳", None))

    def open_settings(self, MainWindow) -> None:
        """Slot function to launch the user settings dialog

        Called by the clicked signal of the settings button.

        Parameters
        ----------
        MainWindow : MainWindow
            Instance of the application's main window.
        """

        settings_dialog = QDialog(MainWindow)
        settings_dialog.ui = Ui_SettingsDialog(settings_dialog, self.user_settings)
        settings_dialog.exec()

    def open_file_info(self, MainWindow) -> None:
        """Slot function to launch the file information dialog for a global selected item.

        Called by the clicked signal of the file info button.

        Parameters
        ----------
        MainWindow : MainWindow
            Instance of the application's main window.
        """

        global selected_file_items
        global selected_uname
        if selected_file_items:
            selected_item = selected_file_items[0]
            size = selected_item["size"]
            filedata = {
                "name": selected_item["name"],
                "hash": selected_item["hash"] or "Not available",
                "type": selected_item["type"],
                "size": convert_size(size or 0),
                "owner": selected_uname,
            }
            if selected_item["type"] != "file":
                size, count = get_directory_size(selected_item, 0, 0)
                filedata["size"] = convert_size(size)
                filedata["count"] = f"{count} files"
            file_info_dialog = QDialog(MainWindow)
            file_info_dialog.ui = Ui_FileInfoDialog(file_info_dialog, filedata, self.download_files)
            file_info_dialog.exec()

    def import_files(self) -> None:
        """Slot function to launch a file picker for importing file symlinks.

        Called by the clicked signal of the add files button.
        """

        global server_socket_mutex
        files, _ = QFileDialog.getOpenFileNames(self, "Import Files", str(Path.home()), "All Files (*)")
        for file in files:
            imported = import_file_to_share(Path(file), Path(self.user_settings["share_folder_path"]))
            if imported is not None:
                print(f"Imported file {imported}")
        # Provide up-to-date share directory data to server
        server_socket_mutex.lock()
        update_share_data(Path(self.user_settings["share_folder_path"]), client_send_socket)
        server_socket_mutex.unlock()

    def import_folder(self) -> None:
        """Slot function to launch a file picker for importing folder symlinks.

        Called by the clicked signal of the add folder button.
        """

        global server_socket_mutex

        dir = QFileDialog.getExistingDirectory(self, "Import Folder", str(Path.home()), QFileDialog.ShowDirsOnly)
        if dir == "":
            return
        imported = import_file_to_share(Path(dir), Path(self.user_settings["share_folder_path"]))
        if imported is not None:
            print(f"Imported file {imported}")
        # Provide up-to-date share directory data to server
        server_socket_mutex.lock()
        update_share_data(Path(self.user_settings["share_folder_path"]), client_send_socket)
        server_socket_mutex.unlock()

    def share_file(self) -> None:
        """Slot function to launch a file picker for a direct file transfer.

        Called by the clicked signal of the send file button.
        Starts a thread to perform the transfer.
        """

        filepath, _ = QFileDialog.getOpenFileName(self, "Send Files", str(Path.home()), "All Files (*)")
        if filepath == "":
            return

        # Create thread to send a file
        self.send_file_thread = QThread()
        self.send_file_worker = SendFileWorker(Path(filepath))
        self.send_file_worker.moveToThread(self.send_file_thread)
        self.send_file_thread.started.connect(self.send_file_worker.run)  # type: ignore
        self.send_file_worker.sending_file.connect(self.messages_controller)
        self.send_file_worker.completed.connect(self.send_file_thread.quit)
        self.send_file_worker.completed.connect(self.send_file_worker.deleteLater)
        self.send_file_thread.finished.connect(self.send_file_thread.deleteLater)  # type: ignore

        self.send_file_thread.start(QThread.HighPriority)  # type: ignore

    def pause_download(self, path: Path) -> None:
        """Slot function to pause an active download.

        Called by the pause_download signal.
        This method updates the global transfer progress object to reflect the paused status for a given item.

        Parameters
        ----------
        path : Path
            Path to the item to pause. This path should exist in the client's temp folder.
        """

        logging.debug(f"Paused file {path}")
        # Set transfer statuses to paused to notify relevant threads to halt the transfer
        if path.is_file():
            transfer_progress[path]["status"] = TransferStatus.PAUSED
        else:
            for (pathname, progress) in transfer_progress.items():
                if path in pathname.parents:
                    if progress["status"] in [
                        TransferStatus.DOWNLOADING,
                        TransferStatus.NEVER_STARTED,
                    ]:
                        transfer_progress[pathname]["status"] = TransferStatus.PAUSED

    def resume_download(self, path: Path) -> None:
        """Slot function to resume a paused download.

        Called by the resume_download signal.
        This method updates the global transfer progress object to reflect the resumed status for a given item.
        New file download workers are created and submitted to a global thread pool instance.

        Parameters
        ----------
        path : Path
            Path to the item to pause. This path should exist in the client's temp folder.
        """

        global transfer_progress
        # Get relative path from temp folder
        relative_path = path.relative_to(TEMP_FOLDER_PATH)
        # Extract sender username from temp path
        uname = str(relative_path.parents[-2])
        peer_ip = request_ip(uname, client_send_socket)
        logging.debug(msg=f"resuming for peer ip {peer_ip}")
        if peer_ip is None:
            logging.debug(msg=f"\nUser with username {uname} not found")
            show_error_dialog(f"Owner of this item is not available at the moment")
            # TODO: auto switch progress bar to paused state
            return
        pool = QThreadPool.globalInstance()
        # Start file download
        if path.is_file():
            file_item: DirData = {
                "name": path.name,
                "path": str(relative_path).removeprefix(uname + "/"),
                "type": "file",
                "size": 0,
                "hash": None,
                "compression": CompressionMethod.NONE,
                "children": None,
            }
            # Update transfer progress
            transfer_progress[path]["status"] = TransferStatus.DOWNLOADING
            # Start file request thread in pool
            worker = RequestFileWorker(file_item, peer_ip, uname, None)
            worker.signals.file_progress_update.connect(self.update_file_progress)
            worker.signals.file_download_complete.connect(self.remove_progress_widget)
            pool.start(worker, QThread.TimeCriticalPriority)  # type: ignore
        elif path.is_dir():
            # Obtain paused files in requested directory
            paused_items: list[DirData] = []
            for (pathname, progress) in transfer_progress.items():
                if path in pathname.parents:
                    if progress["status"] == TransferStatus.PAUSED:
                        transfer_progress[pathname]["status"] = TransferStatus.DOWNLOADING
                        paused_items.append(
                            {
                                "name": pathname.name,
                                "path": str(pathname.relative_to(TEMP_FOLDER_PATH / uname)),
                                "type": "file",
                                "size": 0,
                                "hash": None,
                                "compression": CompressionMethod.NONE,
                                "children": None,
                            }
                        )

            # Update transfer progress
            for file in paused_items:
                transfer_progress[TEMP_FOLDER_PATH / uname / file["path"]]["status"] = TransferStatus.DOWNLOADING

            # Start file request threads in pool
            for file in paused_items:
                request_file_worker = RequestFileWorker(file, peer_ip, uname, path)
                request_file_worker.signals.dir_progress_update.connect(self.update_dir_progress)
                pool.start(request_file_worker, QThread.TimeCriticalPriority)  # type: ignore

    def remove_progress_widget(self, path: Path) -> None:
        """UI utility method to clear progress widget for a completed download.

        A notification is sent at this stage to inform the user of the download's completion.

        Parameters
        ----------
        path : Path
            Path to completed item.
        """

        global progress_widgets
        if user_settings["show_notifications"]:
            notif = Notify()
            notif.application_name = "Drizzle"
            notif.title = "Download complete"
            notif.message = f"{path.name} downloaded to {user_settings['downloads_folder_path']}"
            notif.send()
        widget = progress_widgets.get(path)
        if widget is not None:
            self.vBoxLayout_ScrollContents.removeWidget(widget)
            del progress_widgets[path]
        else:
            logging.info(f"Could not find progress widget for {path}")

    def new_file_progress(self, data: tuple[Path, int, bool]) -> None:
        """UI utility method to render a new progress widget for a new or resumed download.

        Parameters
        ----------
        data : tuple[Path, int]
            Initial data provided to progress widget.
            Pairs an item's path with its total size.
        """

        global progress_widgets
        file_progress_widget = QWidget(self.scrollContents_FileProgress)
        file_progress_widget.ui = Ui_FileProgressWidget(
            file_progress_widget, data[0], data[1], self.signals.pause_download, self.signals.resume_download, data[2]
        )
        self.vBoxLayout_ScrollContents.addWidget(file_progress_widget)
        progress_widgets[data[0]] = file_progress_widget

    def update_file_progress(self, path: Path) -> None:
        """Method to update the progress indicator for a downloading file.

        New progress amount is obtained from the global transfer progress dictionary.

        Parameters
        ----------
        path : Path
            Path to downloading file.
        """

        global transfer_progress
        global progress_widgets
        logging.debug(f"progress_widgets: {progress_widgets}")
        if progress_widgets.get(path) is not None and transfer_progress.get(path) is not None:
            progress_widgets[path].ui.update_progress(transfer_progress[path]["progress"])

    def update_dir_progress(self, progress_data: tuple[Path, int]) -> None:
        """Method to update the progress indicator for a downloading folder.

        New progress amount is obtained from the global directory progress dictionary and provided increment value.

        Parameters
        ----------
        progress_data : tuple[Path, int]
            Pairs directory path to an increment in progress.
        """

        global dir_progress
        global progress_widgets
        path, increment = progress_data
        dir_progress[path]["mutex"].lock()
        dir_progress[path]["current"] += increment
        if dir_progress[path]["current"] == dir_progress[path]["total"]:
            self.remove_progress_widget(path)
        else:
            progress_widgets[path].ui.update_progress(dir_progress[path]["current"])
        dir_progress[path]["mutex"].unlock()

    def direct_transfer_controller(self, data: tuple[FileMetadata, socket.socket]) -> None:
        """Method to handle an incoming direct file transfer.

        A message box is displayed to get consent to receive file.
        Corresponding helpers are called based on user choice.

        Parameters
        ----------
        data : tuple[FileMetadata, socket.socket]
            Pairs a metadata object to the sender's socket
        """

        global ip_to_uname
        metadata, peer_socket = data
        username = ip_to_uname[peer_socket.getpeername()[0]]
        # Prevent download of an item that is actively being downloaded

        # Construct user consent message box
        message_box = QMessageBox(self.MainWindow)
        message_box.setIcon(QMessageBox.Question)
        message_box.setWindowTitle("File incoming")
        message_box.setText(f"{username} is trying to send you a file: {metadata['path']}\nDo you want to accept?")
        btn_Accept = message_box.addButton(QMessageBox.Yes)
        btn_Reject = message_box.addButton(QMessageBox.No)
        # If user accepts file
        btn_Accept.clicked.connect(lambda: self.direct_transfer_accept(metadata, username, peer_socket))  # type: ignore
        # If user rejects file
        btn_Reject.clicked.connect(lambda: self.direct_transfer_reject(peer_socket))  # type: ignore
        message_box.exec()

    def direct_transfer_accept(self, metadata: FileMetadata, sender: str, peer_socket: socket.socket) -> None:
        """Helper method for accepting a direct transfer request.

        Creates a new socket for receiving file and sends new port to the sender.
        Creates a worker to receive file and submits it to an instance of the global thread pool.

        Parameters
        ----------
        metadata : FileMetadata
            Metadata object for incoming file
        sender : str
            Username of sender
        peer_socket : socket.socket
            Socket of sender
        """
        # Create new socket for receiving file
        file_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        file_recv_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        file_recv_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0x10 | 0x08)
        file_recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY, 0x06)
        file_recv_socket.bind((CLIENT_IP, 0))
        file_recv_socket.listen()
        file_recv_port = file_recv_socket.getsockname()[1]
        logging.debug(f"file recv on port {file_recv_port}")
        # Notify sender of the new port
        response = str(file_recv_port).encode(FMT)
        response_header = f"{HeaderCode.DIRECT_TRANSFER_REQUEST.value}{len(response):<{HEADER_MSG_LEN}}".encode(FMT)
        peer_socket.send(response_header + response)
        logging.debug("file accepted")
        # Start file receive thread in pool
        recv_direct_transfer_worker = ReceiveDirectTransferWorker(metadata, sender, file_recv_socket)
        recv_direct_transfer_worker.signals.receiving_new_file.connect(self.new_file_progress)
        recv_direct_transfer_worker.signals.file_progress_update.connect(self.update_file_progress)
        recv_direct_transfer_worker.signals.file_download_complete.connect(self.remove_progress_widget)
        recv_direct_transfer_worker.signals
        recv_direct_transfer_pool = QThreadPool.globalInstance()
        recv_direct_transfer_pool.start(recv_direct_transfer_worker, QThread.TimeCriticalPriority)  # type: ignore

    def direct_transfer_reject(self, peer_socket: socket.socket) -> None:
        """Helper method for rejecting a direct transfer request.

        Sends a rejection message (-1) to the sender.

        Parameters
        ----------
        peer_socket : socket.socket
            Socket of sender
        """

        # Notify sender that file was rejected
        rejection = b"-1"
        rejection_header = f"{HeaderCode.DIRECT_TRANSFER_REQUEST}{len(rejection):<{HEADER_MSG_LEN}}".encode(FMT)
        peer_socket.send(rejection_header + rejection)

    def open_global_search(self, MainWindow) -> None:
        """Slot function to open the file search dialog.

        Parameters
        ----------
        MainWindow : MainWindow
            Instance of the application's main window.
        """

        signals = Signals()
        global_search_dialog = QDialog(MainWindow)
        global_search_dialog.ui = Ui_FileSearchDialog(
            global_search_dialog, client_send_socket, server_socket_mutex, signals.start_download
        )
        global_search_dialog.ui.start_download.connect(self.download_from_global_search)
        global_search_dialog.exec()

    def download_from_global_search(self, item: ItemSearchResult) -> None:
        """Slot function to start download for a search result

        Connected to the start_download signal.

        Parameters
        ----------
        item : ItemSearchResult
            The selected search result object.
        """

        global selected_file_items
        global selected_uname
        # Temporarily set selected items using search dialog data
        selected_file_items = [item["data"]]
        selected_uname = item["owner"]
        # Run download method
        self.download_files()
        # Reset selected items
        self.on_file_item_selected()
        items = self.lw_OnlineStatus.selectedItems()
        if len(items):
            item = items[0]
            username: str = item.data(Qt.UserRole)  # type: ignore
            selected_uname = username
