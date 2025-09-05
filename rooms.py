from db import cur
import string
import random


def code() -> str:
    result = ''.join(random.choice(string.ascii_uppercase +
                     string.digits) for _ in range(7))
    # Surely this will never infinitely loop haha
    if cur.execute(f'SELECT id FROM rooms WHERE id = \'{result}\'').fetchall():
        return code()
    return result


# Returns a room code and creates the room :)
def create(uuid: str) -> str:
    room_code = code()
    cur.execute("INSERT INTO rooms (code, admin) VALUES (?,?);", (room_code, uuid))
    cur.execute("UPDATE users SET room = ? WHERE uuid = ?", (cur.lastrowid, uuid))
    return room_code
