from fastapi import APIRouter, Request, HTTPException
import json
from fastapi.param_functions import Body
from jose.exceptions import JOSEError, JWEError, JWKError
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic.main import BaseModel
import pytz
import requests
import sys
import traceback
from typing import List
from datetime import datetime, timedelta
from jose import jwe

from .models.mongodb_models2 import \
    IdpDomainConfig, \
    RoleConfig
from .models.user_information2 import Credentials, UserInformation
from .models.enums2 import AuthType, Roles
from .models.token import Token


database: AsyncIOMotorDatabase = None


def init_app(db):
    global database
    database = db


app = APIRouter()


async def get_role_config(
    database: AsyncIOMotorDatabase,
    domain: str
) -> List[RoleConfig]:
    if domain:
        return database.role_config.find({
            'enabled': True,
            'domain': domain
        })
    return None


async def roles_by_user_groups(
    database: AsyncIOMotorDatabase,
    user: str,
    groups: List[str],
    domain: str
) -> List[Roles]:
    role_configs = await get_role_config(database, domain)
    roles: list[str] = []
    if user and groups:
        for role_config in await role_configs.to_list(None):
            role_config_obj = RoleConfig(**role_config)
            for auth_config in role_config_obj.auth_config:
                if str(auth_config.auth_type) == str(AuthType.GROUP):
                    if auth_config.name in groups:
                        roles.append(role_config_obj.role)
                elif auth_config.auth_type == AuthType.USER:
                    if auth_config.name == user:
                        roles.append(role_config_obj.role)
    return roles


def decrypt_token(encrypted_token: str, key: str) -> Token:
    try:
        decrypted_token = jwe.decrypt(
            encrypted_token.encode('utf-8'), key
        ).decode('utf-8')
        return Token(**json.loads(decrypted_token))
    except (JOSEError, JWKError, JWEError):
        traceback.print_exc(file=sys.stderr)
    return None


async def route_authorization(request: Request, call_next):
    if 'Authorization' in request.headers:
        token = get_token(request)
        decrypted_token = decrypt_token(token, request.state.secret_key)
        token_is_valid = check_session_token(decrypted_token)
        if token_is_valid:
            user_information = \
                await user_information_by_credentials(decrypted_token)
            groups = user_information.groups
            user = user_information.username
            domain = get_domain(decrypted_token.username)
            roles_found = await roles_by_user_groups(
                request.state.database, user, groups, domain)
            request.state.roles = roles_found
            request.state.user_information = user_information
            request.state.token = decrypted_token
            return await call_next(request)
    request.state.roles = None
    return await call_next(request)


class RolesRequiredChecker:
    def __init__(self, roles: List[str] = []):
        self.roles = roles

    def __call__(self, request: Request):
        if request.state.roles:
            for role in self.roles:
                if role in request.state.roles:
                    return True
            raise HTTPException(detail={
                'status': 'User doesn\'t have the appropriate roles assigned'
            }, status_code=403)
        raise HTTPException(detail={
            'status': 'Authentication required'
        }, status_code=403)


def roles_required(roles=[]):
    def decorator(function):
        async def inner_function(request2: Request = None, *args, **kwargs):
            print(request2)
            if request2.state.roles:
                for role in roles:
                    if role in request2.state.roles:
                        var_names = function.__code__.co_varnames
                        if 'request' in var_names:
                            kwargs['request'] = \
                                request2
                        return await function(*args, **kwargs)
                raise HTTPException(detail={
                    'status': 'User doesn\'t have the appropriate roles assigned'
                }, status_code=403)
            raise HTTPException(detail={
                'status': 'Authentication required'
            }, status_code=403)

        # Fix signature of wrapper
        import inspect
        inner_function.__signature__ = inspect.Signature(
            parameters=[
                # Use all parameters from handler
                *inspect.signature(function).parameters.values(),

                # Skip *args and **kwargs from wrapper parameters:
                *filter(
                    lambda p: p.kind not in (
                        inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD),
                    inspect.signature(inner_function).parameters.values()
                )
            ],
            return_annotation=inspect.signature(function).return_annotation,
        )
        return inner_function
    return decorator


def get_token(request: Request) -> str:
    return request.headers['Authorization'][len('Bearer '):]


async def get_user_information(request: Request) -> UserInformation:
    token = get_token()
    if token:
        decrypted_token = decrypt_token(token, request.state.secret_key)
        if decrypted_token:
            return await user_information_by_credentials(decrypted_token)
    return None


async def user_information_by_credentials(
    token: Token
) -> UserInformation:
    headers = {'content-type': 'application/json'}
    api_endpoints = await get_user_information_endpoint(token.username)
    for api_endpoint in api_endpoints:
        authentication_response = requests.post(
            api_endpoint,
            data=token.json(),
            headers=headers
        )
        if authentication_response.status_code == 200:
            response = authentication_response.json()
            keys = UserInformation.__fields__
            if all(k in response for k in keys):
                return UserInformation(**response)
    return None


def check_session_token(token: Token):
    if token:
        # check, if jwt token is still valid
        expiration_date = token.exp
        exp = datetime.fromtimestamp(expiration_date, tz=pytz.UTC)
        now = datetime.now(tz=pytz.UTC)
        if exp > now:
            return True
    return False


def get_domain(username):
    if '@' in username:
        domain = username.split('@')
        if len(domain) == 2:
            return domain[1]
    return None


async def get_idp_provider(username):
    domain = get_domain(username)
    if domain:
        return database.idp_domain_config.find({'domain': domain})
    return None


async def get_authentication_endpoint(username):
    idp_config = await get_idp_provider(username)
    if not idp_config:
        return []
    return [
        IdpDomainConfig(**config).idp_system_config.login_endpoint
        for config in await idp_config.to_list(None)
    ]


async def get_user_information_endpoint(username):
    idp_config = await get_idp_provider(username)
    if not idp_config:
        return []
    return [
        IdpDomainConfig(
            **idp_config).idp_system_config.user_information_endpoint
        for idp_config in await idp_config.to_list(None)
    ]


async def get_translate_users_endpoint(username):
    idp_config = await get_idp_provider(username)
    if not idp_config:
        return []
    return [
        IdpDomainConfig(
            **idp_config).idp_system_config.translate_users_endpoint
        for idp_config in await idp_config.to_list(None)
    ]


@app.post('/login')
async def login(credentials: Credentials, request: Request):
    if credentials.username is not None and credentials.password is not None:
        authentication_api_hosts = \
            await get_authentication_endpoint(credentials.username)
        for authentication_api_host in authentication_api_hosts:
            if authentication_api_host:
                headers = {'content-type': 'application/json'}
                authentication_response = requests.post(
                    authentication_api_host,
                    data=credentials.json(),
                    headers=headers
                )
                if authentication_response.status_code == 200:
                    exp: datetime = \
                        datetime.now(tz=pytz.UTC) + timedelta(days=1)
                    token = jwe.encrypt(
                        plaintext=Token(
                            username=credentials.username,
                            password=credentials.password,
                            exp=exp.timestamp()
                        ).json(),
                        key=request.state.secret_key,
                        algorithm='dir',
                        encryption='A256GCM'
                    )
                    return token
    raise HTTPException(detail='authentication failed', status_code=403)


class CheckTokenResponse(BaseModel):
    status: bool


@app.post('/check_token', response_model=CheckTokenResponse)
def check_token(request: Request, token: str = Body(...)) -> CheckTokenResponse:
    decrypted_token = decrypt_token(token, request.state.secret_key)
    if check_session_token(decrypted_token):
        return CheckTokenResponse(status=True)
    return CheckTokenResponse(status=False)


class TranslateUsersRequest(BaseModel):
    object_sids: List[str] = []


@app.post('/translate_users')
@roles_required(roles=['USER'])
async def translate_users(
    users_request: TranslateUsersRequest,
    request: Request
):
    print(users_request)
    object_sids = users_request.object_sids
    if object_sids:
        if type(object_sids) == list:
            headers = {'content-type': 'application/json'}
            token: Token = request.state.token
            api_endpoints = \
                await get_translate_users_endpoint(token.username)
            for api_endpoint in api_endpoints:
                if api_endpoint:
                    translate_users_response = requests.post(
                        api_endpoint,
                        data=json.dumps({
                            'username': token.username,
                            'password': token.password,
                            'object_sids': object_sids
                        }),
                        headers=headers
                    )
                    if translate_users_response.status_code == 200:
                        return [
                            {
                                'object_sid': obj['objectSid'][0],
                                'username': obj['name'][0]
                            }
                            for obj in translate_users_response.json()
                        ]
            raise HTTPException(detail=[], status_code=404)
        raise HTTPException(detail={
            'status': 'object_sids needs to be a list'
        }, status_code=400)
    raise HTTPException(detail={
        'status': 'the following keys are null: object_sids'
    }, status_code=400)


@app.get('/user_profile')
@roles_required(roles=['USER'])
async def user_profile(request: Request):
    user_information: UserInformation = request.state.user_information
    if user_information:
        return {
            'username': user_information.username,
            'user_uid': user_information.user_uid
        }
    raise HTTPException(detail={
        'status': 'user_information could not be obtained'
    }, status_code=400)
