from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
import pytz
from typing import List

from .enums2 import AuthType, Roles


class IdpSystemConfig(BaseModel):
    login_endpoint: str = ''
    user_information_endpoint: str = ''
    translate_users_endpoint: str = ''


class IdpDomainConfig(BaseModel):
    enabled: bool = ''
    created: datetime = datetime.now(pytz.UTC)
    updated: datetime = datetime.now(pytz.UTC)
    domain: str = ''
    idp_system_config: IdpSystemConfig = None


class AuthConfig(BaseModel):
    name: str = ''
    auth_type: AuthType = Field(AuthType.GROUP, alias='auth_type')


class RoleConfig(BaseModel):
    enabled: bool = False
    created: datetime = datetime.now(pytz.UTC)
    updated: datetime = datetime.now(pytz.UTC)
    auth_config: List[AuthConfig] = []
    role: Roles = Roles.Default
    domain: str = ''
    # get all user groups from idp, then filter this table for auth_config
    # and then grant specified role to the user
