from enum import Enum


class ExceptionCode(Enum):
    DISCONNECT = 0
    INVALID_HEADER = 1
    BAD_REQUEST = 2
    NOT_FOUND = 4
    USER_EXISTS = 5


class RequestException(Exception):
    def __init__(self, msg: str, code: ExceptionCode, *args: object) -> None:
        super().__init__(*args)
        self.msg = msg
        self.code = code

    @classmethod
    def to_dict(cls, exception) -> dict[str, str | int]:
        return {"msg": exception.msg, "code": exception.code.value}

    @classmethod
    def from_dict(cls, data: dict) -> None:
        return cls(msg=data["msg"], code=ExceptionCode(data["code"]))
