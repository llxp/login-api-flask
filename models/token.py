from pydantic import BaseModel


class Token(BaseModel):
    username: str = ''
    password: str = ''
    exp: int = 0
