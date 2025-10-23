from collections import defaultdict
import sqlite3

from models.generic import LoggedInUser
from typing import Any, DefaultDict

from models.room import Room
from utils import get_user_from_request

DB = sqlite3.connect("./db/draaft.db")
cur = DB.cursor()

# Setup things


def setup_sqlite():
    cur.execute("""
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code char(7) UNIQUE,
            admin char(32)
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid char(32) UNIQUE,
            username char(32),
            room_code char(7) references rooms(code)
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS status (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid char(32) UNIQUE,
            status char(32)
        );
    """)

    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_rooms_code ON rooms(code);
    """)

    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_users_uuid ON users(uuid);
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_users_room_code ON users(room_code);
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_status_uuid ON status(uuid);
    """)


if __name__ == "__main__":
    setup_sqlite()


def insert_user(username: str, uuid: str) -> bool:
    try:
        cur.execute("INSERT INTO users (uuid, username) VALUES (?,?)",
                    (uuid, username))
        DB.commit()
        return True
    except sqlite3.IntegrityError:
        # UUID already exists
        # TODO: Should this also update usernames? I don't think it really matters
        return False

def insert_update_status(uuid: str, status: str):
    try:
        cur.execute("INSERT INTO status (uuid, status) VALUES (?,?)", (uuid, status))
        DB.commit()
    except sqlite3.IntegrityError:
        # update instead
        cur.execute("UPDATE status SET status = ? WHERE uuid = ?", (status, uuid))
        DB.commit()


def get_user_status(uuid: str) -> str:
    status_res = cur.execute("SELECT status FROM status WHERE uuid = ?", (uuid,)).fetchall()
    if status_res:
        assert isinstance(status_res[0][0], str)
        return status_res[0][0]
    else:
        return "player"


def get_user(username: str, uuid: str) -> LoggedInUser | None:
    """ Gets a user by UUID. If the user does not exist, it is created. """
    # TODO - update username if changed or be dynamic elsewhere
    res = cur.execute("SELECT * FROM users WHERE uuid = ?", (uuid,)).fetchall()
    if not res:
        if not insert_user(username, uuid):
            return None
        return get_user(username, uuid)
    _, uuid, stored_username, room_code = res[0]
    if stored_username != username:
        cur.execute("UPDATE users SET username = ? WHERE uuid = ?", (username, uuid))
        DB.commit()
    return LoggedInUser(username=username, uuid=uuid, room_code=room_code, status=get_user_status(uuid))

def try_get_user(uuid: str) -> LoggedInUser | None:
    res = cur.execute("SELECT * FROM users WHERE uuid = ?", (uuid,)).fetchall()
    if not res:
        return None
    _, uuid, stored_username, room_code = res[0]
    return LoggedInUser(username=stored_username, uuid=uuid, room_code=room_code, status=get_user_status(uuid))

class UUIDState:
    def __init__(self):
        self.connections = 0
memory_db: DefaultDict[str, UUIDState] = defaultdict(lambda: UUIDState())

class PopulatedUser:
    def __init__(self, user: LoggedInUser):
        self.source = user
        self.uuid = user.uuid
        self.state = memory_db[self.uuid]

    # Convenience method. Get the room that this user is in.
    def get_room(self) -> Room | None:
        from rooms import get_user_room_code, get_room_from_code
        rc = get_user_room_code(self.uuid)
        if rc is None:
            return None
        return get_room_from_code(rc)

    def update_status(self, status: str):
        insert_update_status(self.uuid, status)


def populated_user(user: LoggedInUser) -> PopulatedUser:
    return PopulatedUser(user)

def populated_users(room: Room) -> list[PopulatedUser]:
    l = [try_get_user(u) for u in room.members]
    return [populated_user(u) for u in l if u is not None]

def get_populated_user_from_request(request) -> PopulatedUser | None:
    u = get_user_from_request(request)
    if u is None:
        return None
    return populated_user(u)

def get_active_user_from_request(request) -> tuple[PopulatedUser, Room] | None:
    u = get_populated_user_from_request(request)
    if u is None:
        return None
    r = u.get_room()
    if r is None:
        return None
    return (u, r)

def get_admin_from_request(request) -> tuple[PopulatedUser, Room] | None:
    ad = get_active_user_from_request(request)
    if ad is None:
        return None
    u, r = ad
    if u.uuid != r.admin:
        return None
    return (u, r)

def update_user(user: LoggedInUser, key: str, value: Any):
    cur.execute("UPDATE users SET ? = ? WHERE uuid = ?", (key, value, user.uuid))
    DB.commit()
