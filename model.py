from pydantic import BaseModel

class LoggedInUser(BaseModel):
    username: str
    uuid: str

    room: str | None = None


