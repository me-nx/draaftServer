from typing import Annotated, Awaitable, Callable, Any, Coroutine, TypeVar
from fastapi import FastAPI, Form, HTTPException, Header, Request, Response, status
from fastapi.responses import PlainTextResponse, HTMLResponse
from enum import Enum
from pydantic import BaseModel
import re
import aiohttp
import string
import json
import hashlib
import time
import hmac
import random
from fastapi.middleware.cors import CORSMiddleware

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

database: dict[str, LoggedInUser] = {

}

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

    x = hmac.new(key=random.randbytes(15), msg=mi.serverID.encode('ascii'), digestmod=hashlib.sha256)
    x.update(respdata['id'].encode('ascii'))
    x.update(str(time.time()).encode('ascii'))

    token = x.hexdigest()

    user = LoggedInUser(username=respdata['name'], uuid=respdata['id'],
                                      token=token, serverID=mi.serverID)
                                      
    database[token] = user
    return AuthenticationSuccess(token=user.token)

class AuthenticateAppForm(BaseModel):
    token: str

@app.post("/authenticate-app", response_class=HTMLResponse)
async def authenticate_app(form: Annotated[AuthenticateAppForm, Form()], request: Request, response: Response):
    origin = request.headers.get('origin')

    if origin is not None and re.match(r"^https?://localhost:\d{1,5}$", origin) is not None:
        response.headers.append('Access-Control-Allow-Origin', origin)

    if not str.isalnum(form.token):
        return Response(status_code=400, content="invalid token")

    return f"""
    <!DOCTYPE html>
    <html>
        <head>
            <title>Redirecting...</title>
            <script>
                window.localStorage.setItem('draaft.token', '{form.token}');
                const url = new URL(window.location.href);
                url.pathname = '/';
                window.location.replace(url);
            </script>
        </head>
        <body>
            <h1>Redirecting...</h1>
        </body>
    </html>
    """

@app.get('/', response_class=HTMLResponse)
async def temp_index():
    return '''
    hello world
    '''

@app.middleware("http")
async def check_valid(request: Request, call_next):
    request.state.valid_token = None

    public_routes = {
        '/',
        '/authenticate',
        '/authenticate-app'
    }

    if request.url.path not in public_routes:
        x = request.headers.get("token")
        if x is None or x not in database:
            return PlainTextResponse("bad request, sorry mate", status_code=403)
        request.state.valid_token = x

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
    result = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(7))
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
    assert token in database
    return database[token]
