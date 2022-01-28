from pathlib import Path

HEADER_TYPE_LEN = 1
HEADER_MSG_LEN = 15
FMT = "utf-8"
CLIENT_SEND_PORT = 5678
CLIENT_RECV_PORT = 4321
RECV_FOLDER_PATH = Path.home() / Path("Downloads")
SHARE_COMPRESSED_PATH = Path.home() / Path(".Drizzle/compressed")
SHARE_FOLDER_PATH = Path.home() / Path(".Drizzle/share")
TEMP_FOLDER_PATH = Path.home() / Path(".Drizzle/tmp")
USER_SETTINGS_PATH = Path.home() / Path(".Drizzle/db/settings.json")
FILE_BUFFER_LEN = 16 * 2 ** 10  # 16KB
HASH_BUFFER_LEN = 16 * 2 ** 20  # 16MB
COMPRESSION_THRESHOLD = 500 * 2 ** 20  # 500MB
SERVER_RECV_PORT = 1234
MESSAGE_MAX_LEN = 256
ONLINE_TIMEOUT = 15  # seconds
HEARTBEAT_TIMER = 5  # seconds
