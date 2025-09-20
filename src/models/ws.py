from pydantic import BaseModel, Field, ValidationError
from typing import Literal, Union
from enum import Enum

class Heartbeat(BaseModel):
    variant: Literal['<3 you matter']

class RoomActionEnum(str, Enum):
    start = 'start'
    close = 'close'

class RoomAction(BaseModel):
    variant: Literal['roomaction']
    action: RoomActionEnum

class WebSocketMessage(BaseModel):
    message: Union[Heartbeat, RoomAction] = Field(discriminator='variant')

    @staticmethod
    def deserialize(data: str) -> 'WebSocketMessage | None':
        import json
        try:
            # Ignore the type check error here lol, it works
            return WebSocketMessage(message=json.loads(data))
        except Exception as e:
            print(f'Warning: Got a bad deserialize: {e}')
