import re
import aiohttp
import json

from models.model import LoggedInUser


async def validate_mojang_session(username: str, serverID: str):
    uri = getSessionCheckURI(username, serverID)
    if uri is None:
        return {"success": False, "error": "Your data sucks, try harder"}
    async with aiohttp.ClientSession() as session:
        async with session.get(uri) as resp:
            if resp.status != 200:
                return {"success": False, "error": f"Your response error code sucks ({resp.status}), try harder"}
            respdata = await resp.json()
    if 'id' not in respdata or 'name' not in respdata:
        return {"success": False, "error": f"your JSON sucks ({json.dumps(respdata)}), try harder"}
    return {"success": True, "data": respdata}


def get_user_from_request(request) -> LoggedInUser | None:
    token = request.state.valid_token
    if token is None or not hasattr(request.state, 'logged_in_user') or request.state.logged_in_user is None or not isinstance(request.state.logged_in_user, LoggedInUser):
        return None
    return request.state.logged_in_user


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
