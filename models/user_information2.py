from typing import List

from pydantic.main import BaseModel


class UserInformation(BaseModel):
    user_uid: str = ''
    username: str = ''
    groups: List[str] = []


class Credentials(BaseModel):
    username: str = ''
    password: str = ''
