from flask_mongoengine import MongoEngine
from typing import List

from .enums import AuthType, Roles


db = MongoEngine()


def init_app(app):
    db.init_app(app)


class IdpSystemConfig(db.EmbeddedDocument):
    login_endpoint: str = db.StringField()
    user_information_endpoint: str = db.StringField()
    translate_users_endpoint: str = db.StringField()


class IdpDomainConfig(db.Document):
    enabled: bool = db.BooleanField()
    created = db.DateTimeField()
    updated = db.DateTimeField()
    domain = db.StringField()
    idp_system_config = db.EmbeddedDocumentField(IdpSystemConfig)


class AuthConfig(db.EmbeddedDocument):
    name: str = db.StringField()
    auth_type: AuthType = db.StringField()


class RoleConfig(db.Document):
    enabled: bool = db.BooleanField()
    created = db.DateTimeField()
    updated = db.DateTimeField()
    auth_config: List[AuthConfig] = db.EmbeddedDocumentListField(AuthConfig)
    role: Roles = db.StringField()
    # get all user groups from idp, then filter this table for auth_config
    # and then grant specified role to the user
