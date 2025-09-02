import json
import random
import re
import secrets
import string
import time
from enum import Enum
from typing import Annotated, Any, Callable, Coroutine, TypeVar

import aiohttp
import jwt
from fastapi import FastAPI, Form, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

JWT_SECRET = secrets.token_urlsafe(32)
JWT_ALGORITHM = "HS256"

# https://pyjwt.readthedocs.io/en/stable/
# https://sessionserver.mojang.com/session/minecraft/hasJoined?username=DesktopFolder&serverId=draaft2025server


def valid_username(un: str):
    return re.match(r"^[\w\d_]{2,17}$", un) is not None


def valid_serverid(sid: str):
    # Valid drAAft server ID:
    # 24 characters of base32 -> "draaaaft"
    return re.match(r"^[\w\d]{24}draaaaft$", sid) is not None


def getSessionCheckURI(username: str, serverId: str) -> str | None:
    if valid_serverid(serverId) and valid_username(username):
        print(f'Valid login from {username}')
        return f"https://sessionserver.mojang.com/session/minecraft/hasJoined?username={username}&serverId={serverId}"
    return None


app = FastAPI()


class LoggedInUser(BaseModel):
    username: str
    uuid: str
    token: str
    serverID: str

    room: str | None = None


class MojangInfo(BaseModel):
    serverID: str
    username: str


class AuthenticationSuccess(BaseModel):
    token: str


class AuthenticationFailure(BaseModel):
    message: str


AuthenticationResult = AuthenticationSuccess | AuthenticationFailure


@app.post("/authenticate")
async def authenticate(mi: MojangInfo) -> AuthenticationResult:
    uri = getSessionCheckURI(mi.username, mi.serverID)
    if uri is None:
        return AuthenticationFailure(message="Your data sucks, try harder")
    async with aiohttp.ClientSession() as session:
        async with session.get(uri) as resp:
            if resp.status != 200:
                return AuthenticationFailure(message=f"Your response error code sucks ({resp.status}), try harder")
            respdata = await resp.json()
    if 'id' not in respdata or 'name' not in respdata:
        return AuthenticationFailure(message=f"your JSON sucks ({json.dumps(respdata)}), try harder")

    # JWT payload
    payload = {
        "username": respdata['name'],
        "uuid": respdata['id'],
        "serverID": mi.serverID,
        "iat": int(time.time()),
        "exp": int(time.time()) + 60 * 60 * 24  # 24 hours expiry
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return AuthenticationSuccess(token=token)


@app.middleware("http")
async def check_valid(request: Request, call_next):
    request.state.valid_token = None

    public_routes = {
        '/',
        '/authenticate',
        "/docs",
        "/openapi.json",
    }

    if request.url.path not in public_routes:
        token = request.headers.get("token")
        if not token:
            return PlainTextResponse("bad request, sorry mate", status_code=403)
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except jwt.ExpiredSignatureError:
            return PlainTextResponse("token expired", status_code=403)
        except jwt.InvalidTokenError:
            return PlainTextResponse("invalid token", status_code=403)
        request.state.valid_token = token
        request.state.logged_in_user = LoggedInUser(
            username=payload["username"], uuid=payload["uuid"], serverID=payload["serverID"], token=token)

    return await call_next(request)

app.add_middleware(
    CORSMiddleware,
    allow_origins=('*'),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class Room(BaseModel):
    code: str
    members: set[str]

    # Room creator UUID
    admin: str


rooms: dict[str, Room] = {

}


class RoomManager:
    def __init__(self):
        pass


def room_code() -> str:
    result = ''.join(random.choice(string.ascii_uppercase +
                     string.digits) for _ in range(7))
    # Surely this will never infinitely loop haha
    if result in rooms:
        return room_code()
    return result


@app.get("/authenticated")
async def is_authenticated():
    return True


class RoomJoinState(str, Enum):
    created = "created"
    rejoined = "rejoined"
    rejoined_as_admin = "rejoined_as_admin"
    joined = "joined"


class RoomIdentifier(BaseModel):
    code: str


class RoomResult(RoomIdentifier):
    state: RoomJoinState


class APIError(BaseModel):
    error_message: str


class RoomJoinError(APIError):
    pass


APIErrorType = TypeVar('APIErrorType')


def api_error(error: APIErrorType, response: Response, code=status.HTTP_400_BAD_REQUEST) -> APIErrorType:
    response.status_code = code
    return error


async def handle_room_rejoin(u: LoggedInUser, cb: Callable[[], Coroutine[Any, Any, RoomResult]]) -> RoomResult | None:
    if u.room is not None:
        if u.room not in rooms:
            # Handle room timeout / deletion
            u.room = None
            return await cb()
        room = rooms[u.room]
        if u.uuid == room.admin:
            return RoomResult(code=room.code, state=RoomJoinState.rejoined_as_admin)
        return RoomResult(code=room.code, state=RoomJoinState.rejoined)
    return None


@app.get("/room")
async def get_room(request: Request, response: Response) -> Room | APIError:
    u = await get_user(request)
    if u.room is None or u.room not in rooms:
        return api_error(APIError(error_message="no room found for user"), response, status.HTTP_404_NOT_FOUND)
    return rooms[u.room]


@app.get("/room/create")
async def create_room(request: Request) -> RoomResult:
    # The user must be authenticated to get this.
    # Only create a room if the user is not already joined to a room.
    u = await get_user(request)
    rejoin_result = await handle_room_rejoin(u, lambda: create_room(request))
    if rejoin_result is not None:
        return rejoin_result
    new_code = room_code()
    rooms[new_code] = Room(code=new_code, members={u.uuid}, admin=u.uuid)
    return RoomResult(code=new_code, state=RoomJoinState.created)


@app.post("/room/join")
async def join_room(request: Request, response: Response, room_id: RoomIdentifier) -> RoomResult | RoomJoinError:
    u = await get_user(request)
    rejoin_result = await handle_room_rejoin(u, lambda: create_room(request))
    if rejoin_result is not None:
        return rejoin_result
    if room_id.code not in rooms:
        return api_error(RoomJoinError(error_message=f"no such room: {room_id.code}"), response)
    # User can join this room!
    u.room = room_id.code
    rooms[room_id.code].members.add(u.uuid)
    return RoomResult(code=room_id.code, state=RoomJoinState.joined)


@app.get("/user")
async def get_user(request: Request) -> LoggedInUser:
    token = request.state.valid_token
    assert token is not None
    assert hasattr(request.state, 'logged_in_user')
    return request.state.logged_in_user
