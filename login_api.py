from flask import Blueprint, request, current_app, jsonify
from flask_cors import cross_origin
import json
import pytz
import requests
import sys
import traceback
from typing import List
from datetime import datetime, timedelta
from functools import wraps
import jwt
from jwt import \
    DecodeError, MissingRequiredClaimError, \
    InvalidIssuedAtError, ImmatureSignatureError, \
    ExpiredSignatureError

from .models.mongodb_models import \
    AuthConfig, IdpDomainConfig, \
    RoleConfig, init_app as iam
from .models.user_information import UserInformation
from .utils.decorator_utils import composed
from .models.enums import AuthType, Roles


app = Blueprint(
    'login_api',
    __name__)


def init_app(app):
    iam(app)

# authentication_api_host = \
#     os.getenv('AUTHENTICATION_API_HOST', 'http://127.0.0.1:5002')
# os.getenv('AUTHENTICATION_API_HOST', 'http://192.168.6.1:8083')


def get_domain(username):
    if '@' in username:
        domain = username.split('@')
        if len(domain) == 2:
            return domain[1]
    return None


def get_idp_provider(username):
    domain = get_domain(username)
    if domain:
        idp_config: IdpDomainConfig = \
            IdpDomainConfig.objects(domain=domain)
        # new_idp = IdpDomainConfig()
        # new_idp.domain = "ad.local"
        # new_idp.created = datetime.utcnow()
        # new_idp.updated = datetime.utcnow()
        # new_idp.idp_system_config = IdpSystemConfig()
        # new_idp.idp_system_config.login_endpoint = "http://127.0.0.1:5002/api/login"
        # new_idp.idp_system_config.user_information_endpoint = "http://127.0.0.1:5002/api/get_user_groups"
        # new_idp.idp_system_config.translate_users_endpoint = "http://127.0.0.1:5002/api/translate_users"
        # new_idp.save()
        return idp_config
    return []


def get_authentication_endpoint(username):
    idp_config = get_idp_provider(username)
    if not idp_config:
        return []
    return [
        idp_config.idp_system_config.login_endpoint
        for idp_config in idp_config
    ]


def get_user_information_endpoint(username):
    idp_config = get_idp_provider(username)
    if not idp_config:
        return []
    return [
        idp_config.idp_system_config.user_information_endpoint
        for idp_config in idp_config
    ]


def get_translate_users_endpoint(username):
    idp_config = get_idp_provider(username)
    if not idp_config:
        return []
    return [
        idp_config.idp_system_config.translate_users_endpoint
        for idp_config in idp_config
    ]


def get_credentials_from_token(token: str):
    if token:
        try:
            key = current_app.config['SECRET_KEY']
            decoded_jwt = jwt.decode(jwt=token, key=key)
            if (
                'username' in decoded_jwt
                and 'password' in decoded_jwt
                and 'exp' in decoded_jwt
            ):
                return {
                    'username': decoded_jwt['username'],
                    'password': decoded_jwt['password'],
                    'exp': decoded_jwt['exp']
                }
        except (
            DecodeError,
            TypeError,
            MissingRequiredClaimError,
            InvalidIssuedAtError,
            ImmatureSignatureError,
            ExpiredSignatureError
        ):
            traceback.print_exc(file=sys.stdout)
            return None
    return None


def get_user_profile():
    token = get_token()
    credentials = get_credentials_from_token(token)
    if credentials:
        return get_user_information(
            credentials['username'],
            credentials['password']
        )
    return None


def authentication_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if 'Authorization' in request.headers:
            token = get_token()
            token_is_valid = check_session_token(token)
            if not token_is_valid:
                return jsonify('Authentication required'), 403
        else:
            return jsonify('Authentication required'), 403
        return function(*args, **kwargs)
    return wrapper


def roles_required(roles=[]):
    def decorator(function):
        @wraps(function)
        def inner_function(*args, **kwargs):
            if 'Authorization' in request.headers:
                token = get_token()
                token_is_valid = check_session_token(token)
                if token_is_valid:
                    credentials = get_credentials_from_token(token)
                    if credentials:
                        user_information = \
                            user_information_by_credentials(credentials)
                        groups = user_information.groups
                        user = user_information.username
                        roles_found = roles_by_user_groups(user, groups)
                        for role in roles:
                            if role in roles_found:
                                var_names = function.__code__.co_varnames
                                if 'user_information' in var_names:
                                    kwargs['user_information'] = \
                                        user_information
                                return function(*args, **kwargs)
                        return jsonify(
                            'User doesn\'t have the appropriate roles assigned'
                        ), 403
            return jsonify('Authentication required'), 403
        return inner_function
    return decorator


def route_authorization(
    self,
    route: str,
    roles: List[str],
    methods: List[str] = ['GET']
):
    return composed(
        self.route(route, methods=methods),
        cross_origin(supports_credentials=True),
        roles_required(roles=['USER'])
    )


def get_user_authorization(self, route: str):
    return route_authorization(self, route, roles=['USER'], methods=['GET'])


def get_token() -> str:
    return request.headers['Authorization'][len('Bearer '):]


def get_user_information() -> UserInformation:
    token = get_token()
    if token:
        credentials = get_credentials_from_token(token)
        if credentials:
            return user_information_by_credentials(credentials)
    return None


def check_auth(groups: List[str], user_name: str, auth_config: AuthConfig):
    for entry in auth_config:
        if (
            str(entry.auth_type) == str(AuthType.GROUP) and
            entry.name in groups
        ):
            return True
        if (
            str(entry.auth_type == AuthType.USER) and
            entry.name in user_name
        ):
            return True
    return False


def user_information_by_credentials(
    credentials: {'username': str, 'password': str}
) -> UserInformation:
    return get_user_information_by_username_password(
        credentials['username'], credentials['password'])


def get_user_information_by_username_password(
    username,
    password
) -> UserInformation:
    headers = {'content-type': 'application/json'}
    api_endpoints = get_user_information_endpoint(username)
    for api_endpoint in api_endpoints:
        authentication_response = requests.post(
            api_endpoint,
            data=json.dumps({'username': username, 'password': password}),
            headers=headers
        )
        if authentication_response.status_code == 200:
            response = authentication_response.json()
            keys = UserInformation.__dataclass_fields__
            if all(k in response for k in keys):
                return UserInformation(**response)
    return None


def check_session_token(token: str):
    try:
        key = current_app.config['SECRET_KEY']
        decoded_jwt = jwt.decode(jwt=token, key=key)
        if 'username' in decoded_jwt and 'exp' in decoded_jwt:
            # check, if jwt token is still valid
            expiration_date = decoded_jwt['exp']
            exp = datetime.fromtimestamp(expiration_date, tz=pytz.UTC)
            now = datetime.now(tz=pytz.UTC)
            if exp > now:
                return True
    except (
        DecodeError,
        TypeError,
        MissingRequiredClaimError,
        InvalidIssuedAtError,
        ImmatureSignatureError,
        ExpiredSignatureError
    ):
        # traceback.print_exc(file=sys.stdout)
        return False
    return False


@app.route('/login', methods=['POST'])
@cross_origin(supports_credentials=True)
def login():
    json_body = request.json
    if json_body is not None:
        if (
            'username' in json_body and
            'password' in json_body
        ):
            username: str = json_body['username']
            password: str = json_body['password']
            headers = {'content-type': 'application/json'}
            authentication_api_hosts = get_authentication_endpoint(username)
            for authentication_api_host in authentication_api_hosts:
                # authentication_api_host = \
                #     current_app.config['AUTHENTICATION_API_HOST']
                if len(authentication_api_host) > 0:
                    authentication_response = requests.post(
                        authentication_api_host,
                        # authentication_api_host + '/api/login',
                        data=json.dumps(
                            {'username': username, 'password': password}
                        ),
                        headers=headers
                    )
                    if authentication_response.status_code == 200:
                        exp: datetime = \
                            datetime.now(tz=pytz.UTC) + timedelta(days=1)
                        token = jwt.encode(
                            payload={
                                'username': username,
                                'password': password,
                                'exp': exp.timestamp()
                            },
                            key=current_app.config['SECRET_KEY']
                        )
                        return jsonify(token.decode('utf-8'))
            return jsonify('authentication failed'), 403
            # return jsonify('authentication api host is empty'), 500
        return jsonify(
            'One of the following keys is missing: '
            'username, password'
        ), 403
    return jsonify('json body is missing'), 403


@app.route('/check_token', methods=['POST'])
@cross_origin()
def check_token():
    json_body = request.json
    if json_body is not None:
        if 'token' in json_body:
            token: str = json_body['token']
            if check_session_token(token):
                return jsonify(True), 200
    return jsonify(False), 403


@app.route('/translate_users', methods=['POST'])
@cross_origin(supports_credentials=True)
@roles_required(roles=['USER'])
def translate_users():
    json_body = request.json
    if json_body is not None:
        if 'object_sids' in json_body:
            object_sids = json_body['object_sids']
            if object_sids:
                if type(object_sids) == list:
                    headers = {'content-type': 'application/json'}
                    token = get_token()
                    credentials = get_credentials_from_token(token)
                    # authentication_api_host = \
                    #     current_app.config['AUTHENTICATION_API_HOST']
                    api_endpoints = \
                        get_translate_users_endpoint(credentials['username'])
                    for api_endpoint in api_endpoints:
                        if len(api_endpoint) > 0:
                            translate_users_response = requests.post(
                                api_endpoint,
                                data=json.dumps({
                                    'username': credentials['username'],
                                    'password': credentials['password'],
                                    'object_sids': object_sids
                                }),
                                headers=headers
                            )
                            if translate_users_response.status_code == 200:
                                return jsonify([
                                    {
                                        'object_sid': obj['objectSid'][0],
                                        'username': obj['name'][0]
                                    }
                                    for obj in translate_users_response.json()]
                                ), 200
                        # return jsonify(
                        #     {
                        #         'status':
                        #         translate_users_response
                        #         .content.decode('utf-8')
                        #     }
                        # ), translate_users_response.status_code
                        # return jsonify({
                        #     'status': 'authentication api host is empty'
                        # }), 500
                    return jsonify([]), 404
                return jsonify(
                    {'status': 'object_sids needs to be a list'}), 400
            return jsonify(
                {'status': 'the following keys are null: object_sids'}), 400
        return jsonify(
            {'status': 'the following keys are missing: object_sids'}), 400
    return jsonify('json body is missing'), 400


def get_role_config(domain: str) -> List[RoleConfig]:
    if domain:
        return RoleConfig.objects(enabled=True, domain=domain)
    return []


def roles_by_user_groups(user: str, groups: List[str]) -> List[Roles]:
    role_configs = get_role_config(get_domain(user))
    roles: list[str] = []
    if user and groups:
        for role_config in role_configs:
            for auth_config in role_config.auth_config:
                if str(auth_config.auth_type) == str(AuthType.GROUP):
                    if auth_config.name in groups:
                        roles.append(role_config.role)
                elif auth_config.auth_type == AuthType.USER:
                    if auth_config.name == user:
                        roles.append(role_config.role)
    return roles


@app.route('/roles', methods=['GET'])
@cross_origin(supports_credentials=True)
@roles_required(roles=['USER'])
def roles(user_information: UserInformation):
    groups = user_information.groups
    user = user_information.user_uid
    roles = roles_by_user_groups(user, groups)
    if roles and len(roles) > 0:
        return jsonify(roles), 200
    return jsonify([]), 404


@app.route('/user_profile', methods=['GET'])
@cross_origin(supports_credentials=True)
@roles_required(roles=['USER'])
def user_profile(user_information: UserInformation):
    if user_information:
        return jsonify({
            'username': user_information.username,
            'user_uid': user_information.user_uid
        }), 200
    return jsonify({'status': 'user_information could not be obtained'}), 400
