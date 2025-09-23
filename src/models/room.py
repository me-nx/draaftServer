from enum import Enum
from pydantic import BaseModel

from models.api import APIError


class Room(BaseModel):
    code: str
    members: set[str]

    # Room creator UUID
    admin: str


class RoomJoinState(str, Enum):
    created = "created"
    rejoined = "rejoined"
    rejoined_as_admin = "rejoined_as_admin"
    joined = "joined"


class RoomIdentifier(BaseModel):
    code: str


class RoomResult(RoomIdentifier):
    state: RoomJoinState
    members: list[str]


class RoomJoinError(APIError):
    pass
