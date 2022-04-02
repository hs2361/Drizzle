from pathlib import Path

# Length (bytes) of header codes in a communication
HEADER_TYPE_LEN = 1
# Length (bytes) used to store size of message
HEADER_MSG_LEN = 15
# String encoding format
FMT = "utf-8"
# Port [client-side] for communication from client to server
CLIENT_SEND_PORT = 5678
# Port [client-side] for communication to the client
CLIENT_RECV_PORT = 4321
# Default path for downloads
RECV_FOLDER_PATH = Path.home() / Path("Downloads")
# Path for storing compression data
SHARE_COMPRESSED_PATH = Path.home() / Path(".Drizzle/compressed")
# Default share folder path
SHARE_FOLDER_PATH = Path.home() / Path(".Drizzle/share")
# Path for temp storage of incomplete downloads
TEMP_FOLDER_PATH = Path.home() / Path(".Drizzle/tmp")
# Path for storing user settings
DIRECT_TEMP_FOLDER_PATH = Path.home() / Path(".Drizzle/direct")
# Path for temp storage of incomplete direct downloads
USER_SETTINGS_PATH = Path.home() / Path(".Drizzle/db/settings.json")
# Size of file read buffer
FILE_BUFFER_LEN = 16 * 2 ** 10  # 16KB
# Size of hash calculator buffer
HASH_BUFFER_LEN = 16 * 2 ** 20  # 16MB
# Threshold beyond which compression may be performed
COMPRESSION_THRESHOLD = 500 * 2 ** 20  # 500MB
# Port [server-side] for communication to the server
SERVER_RECV_PORT = 1234
# Maximum size (bytes) for a chat message
MESSAGE_MAX_LEN = 256
# Maximum time past the last active timestamp, after which a user is considered offline
ONLINE_TIMEOUT = 10  # seconds
# Time gap between heartbeats
HEARTBEAT_TIMER = 5  # seconds
# Message area prefix html
LEADING_HTML = """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0//EN" "http://www.w3.org/TR/REC-html40/strict.dtd">
<html>
<head>
<meta name="qrichtext" content="1" />
<style type="text/css">p, li { white-space: pre-wrap; text-align: start }</style>
</head>
<body style=\" font-family:"Noto Sans"; font-size:10pt; font-weight:400; font-style:normal;\">
"""
# Message area suffix html
TRAILING_HTML = """</body>
</html>
"""
