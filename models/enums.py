import enum


class Roles(enum.Enum):
    User = 'USER'
    PlatformAdmin = 'PLATFORM_ADMINISTRATOR'
    ScopeAdmin = 'SCOPE_ADMINISTRATOR'


class AuthType(enum.Enum):
    GROUP = 'GROUP'
    USER = 'USER'
