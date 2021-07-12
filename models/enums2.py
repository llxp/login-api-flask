from enum import Enum


class Roles(str, Enum):
    Default = 'DEFAULT'
    User = 'USER'
    PlatformAdmin = 'PLATFORM_ADMINISTRATOR'
    ScopeAdmin = 'SCOPE_ADMINISTRATOR'


class AuthType(str, Enum):
    GROUP = 'GROUP'
    USER = 'USER'
