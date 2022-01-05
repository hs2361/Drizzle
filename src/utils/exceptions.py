from enum import IntEnum
from typing import TypedDict


class ExceptionCode(IntEnum):
    DISCONNECT = 0
    INVALID_HEADER = 1
    BAD_REQUEST = 2
    NOT_FOUND = 4
    USER_EXISTS = 5


class RequestExceptionDict(TypedDict):
    msg: str
    code: int


class RequestException(Exception):
    def __init__(self, msg: str, code: ExceptionCode, *args: object) -> None:
        super().__init__(*args)
        self.msg = msg
        self.code = code

    @classmethod
    def to_dict(cls, exception: "RequestException") -> RequestExceptionDict:
        return {"msg": exception.msg, "code": exception.code.value}

    @classmethod
    def from_dict(cls, data: RequestExceptionDict) -> "RequestException":
        return cls(msg=data["msg"], code=ExceptionCode(data["code"]))
