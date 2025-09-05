import sqlite3
from model import LoggedInUser

DB = sqlite3.connect("draaft.db")
cur = DB.cursor()

# Setup things
def setup_sqlite():
    cur.execute("""
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code char(7),
            admin char(32)
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid char(32),
            username char(32),
            room INTEGER references rooms(id)
        );
    """)
setup_sqlite()

def insert_user(username: str, uuid: str):
    cur.execute("INSERT INTO users (uuid, username) VALUES (?,?)", (uuid, username))    

def get_user(username: str, uuid: str):
    # TODO - update username if changed or be dynamic elsewhere
    res = cur.execute("SELECT * FROM users WHERE uuid = ?", (uuid,)).fetchall()
    if not res:
        insert_user(username, uuid)
        return get_user(username, uuid)
    if len(res) > 1:
        raise RuntimeError('??? duplicate user? how could you desktopfolder i trusted your code')
    _, uuid, username, room = res[0]
    return LoggedInUser(username=username, uuid=uuid, room=room)
