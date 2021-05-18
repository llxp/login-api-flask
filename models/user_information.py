from dataclasses_json import dataclass_json
from dataclasses import dataclass, field
from typing import List


@dataclass_json
@dataclass(frozen=True)
class UserInformation():
    user_uid: str = ''
    username: str = ''
    groups: List[str] = field(default_factory=list)
