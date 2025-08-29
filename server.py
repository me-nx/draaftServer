from typing import Annotated
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
import re
import aiohttp
import string
import json
import hashlib
import time
import hmac
import random

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

@app.middleware("http")
async def check_valid(request: Request, call_next):
    if request.url.path != '/authenticate':
        x = request.headers.get("token")
        if x is None or x not in database:
            return PlainTextResponse("bad request, sorry mate", status_code=403)

    return await call_next(request)


class Room(BaseModel):
    code: str
    members: list[str]

rooms = {
    
}

def room_code():
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(7))

@app.get("/room/create")
async def create_room():
    return room_code()
