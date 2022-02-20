from enum import IntEnum
from typing import TypedDict


class ExceptionCode(IntEnum):
    """Enumerated exception codes for use in custom exception type"""

    BAD_REQUEST = 0
    DISCONNECT = 1
    INVALID_HEADER = 2
    NOT_FOUND = 3
    USER_EXISTS = 4
    UNAUTHORIZED = 5
    INCOMPLETE = 6


class RequestExceptionDict(TypedDict):
    """Dictionary representation of cutom exception type"""

    msg: str
    code: int


class RequestException(Exception):
    """Custom exception type for client-server communication

    Methods
    -------
    to_dict(exception: "RequestException")
        Object to dictionary conversion helper
    from_dict(data: RequestExceptionDict)
        Dictionary to object conversion helper

    """

    def __init__(self, msg: str, code: ExceptionCode, *args: object) -> None:
        super().__init__(*args)
        self.msg = msg
        self.code = code

    @classmethod
    def to_dict(cls, exception: "RequestException") -> RequestExceptionDict:
        """Object to dictionary conversion helper.

        Required for msgpack compatibility.
        """
        return {"msg": exception.msg, "code": exception.code.value}

    @classmethod
    def from_dict(cls, data: RequestExceptionDict) -> "RequestException":
        """Dictionary to object conversion helper.

        Required for msgpack compatibility.
        """
        return cls(msg=data["msg"], code=ExceptionCode(data["code"]))
