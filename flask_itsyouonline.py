#
# Itsyou.Online authentication helpers for Flask
#
import re
import time
import uuid
from functools import wraps
from urllib.parse import urlencode

import jwt
import requests
from flask import current_app, redirect, request, session

__version__ = '0.0.1'

ITSYOUONLINE = "https://itsyou.online"
JWT_AUTH_HEADER = re.compile("^bearer (.*)$", re.IGNORECASE)
ITSYOUONLINE_KEY = """-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAES5X8XrfKdx9gYayFITc89wad4usrk0n2
7MjiGYvqalizeSWTHEpnd7oea9IQ8T5oJjMVH5cc0H5tFSKilFFeh//wngxIyny6
6+Vq5t5B0V0Ehy01+2ceEon2Y0XDkIKv
-----END PUBLIC KEY-----"""


def configure(app, organization, client_secret, callback_uri, callback_route, scope=None, get_jwt=False, offline_access=False, orgfromrequest=False, invalidate_session_timeout=300, verify=True):
    """
    @param app: Flask app object
    @param organization: Fully qualified Itsyou.Online organization.
                         E.g. root_org.sub_org.sub_sub_org
    @param client_secret: Itsyou.Online organization api key client_secret
    @param callback_uri: Uri Itsyou.Online will target in the oauth flow.
                         Must be the same as the one configured in the Itsyou.Online
                         api key of the corresponding client_secret parameter.
    @param callback_route: Route to bind the callback handler to.
    @param scope: Extra scope to request from Itsyou.Online
    @param get_jwt: Set to True to also create a jwt for the authenticated user
    @param invalidate_session_timeout: Session timeout. Set to 0 for no timeout.
    """
    def invalidate_session():
        authenticated_ = session.get('_iyo_authenticated')
        if not authenticated_ or authenticated_ + invalidate_session_timeout < time.time():
            if '_iyo_authenticated' in session:
                del session['_iyo_authenticated']
            if 'iyo_user_info' in session:
                del session['iyo_user_info']
            if 'iyo_jwt' in session:
                del session['iyo_jwt']

    if invalidate_session_timeout > 0:
        app.before_request(invalidate_session)
    app.config['iyo_config'] = dict(organization=organization, client_secret=client_secret,
                                    callback_uri=callback_uri, callback_route=callback_route,
                                    scope=scope, get_jwt=get_jwt, offline_access=offline_access,
                                    orgfromrequest=orgfromrequest, verify=verify)
    app.add_url_rule(callback_route, '_callback', _callback)


def get_auth_org():
    config = current_app.config["iyo_config"]
    if config['orgfromrequest']:
        return request.values[config['orgfromrequest']]
    else:
        return config['organization']


def authenticated(handler):
    """
    Wraps route handler to be only accessible after authentication via Itsyou.Online
    """
    @wraps(handler)
    def _wrapper(*args, **kwargs):
        if not session.get("_iyo_authenticated"):
            organization = get_auth_org()
            config = current_app.config["iyo_config"]
            scopes = []
            scopes.append("user:memberof:{}".format(organization))
            if config["scope"]:
                scopes.append(config['scope'])
            scope = ','.join(scopes)

            header = request.headers.get("Authorization")
            if header:
                match = JWT_AUTH_HEADER.match(header)
                if match:
                    jwt_string = match.group(1)
                    jwt_info = jwt.decode(jwt_string, ITSYOUONLINE_KEY)
                    jwt_scope = jwt_info["scope"]
                    if set(scope.split(",")).issubset(set(jwt_scope)):
                        username = jwt_info["username"]
                        session["iyo_user_info"] = _get_info(username, jwt=jwt_string)
                        session["_iyo_authenticated"] = time.time()
                        session['iyo_jwt'] = jwt_string
                        return handler(*args, **kwargs)
                return "Could not authorize this request!", 403
            state = str(uuid.uuid4())
            session["_iyo_state"] = state
            session['_iyo_organization'] = organization
            session["_iyo_auth_complete_uri"] = request.full_path
            params = {
                "response_type": "code",
                "client_id": config["organization"],
                "redirect_uri": config["callback_uri"],
                "scope": scope,
                "state" : state
            }
            base_url = "{}/v1/oauth/authorize?".format(ITSYOUONLINE)
            login_url = base_url + urlencode(params)
            return redirect(login_url)
        else:
            return handler(*args, **kwargs)
    return _wrapper


def _callback():
    code = request.args.get("code")
    state = request.args.get("state")
    session_state = session.get("_iyo_state")
    on_complete_uri = session.get("_iyo_auth_complete_uri")
    if not on_complete_uri:
        return "Invalid request.", 400
    if session_state != state:
        return "Invalid state received. Cannot authenticate request!", 400
    if not code:
        return "Invalid code received. Cannot authenticate request!", 400
    # Get access token
    config = current_app.config["iyo_config"]
    organization = config["organization"]
    authorg = session['_iyo_organization']
    params = {
        "code" : code,
        "state": state,
        "grant_type": "authorization_code",
        "client_id" : organization,
        "client_secret": config["client_secret"],
        "redirect_uri": config["callback_uri"],
    }
    base_url = "{}/v1/oauth/access_token?".format(ITSYOUONLINE)
    url = base_url + urlencode(params)
    response = requests.post(url, verify=config['verify'])
    response.raise_for_status()
    response = response.json()
    scope_parts = response["scope"].split(",")
    if not "user:memberof:{}".format(authorg) in scope_parts:
        return "User is not authorized.", 403
    access_token = response["access_token"]
    username = response["info"]["username"]
    # Get user info
    session['iyo_user_info'] = _get_info(username, access_token=access_token)
    session['_iyo_authenticated'] = time.time()
    if config['get_jwt']:
        # Create JWT
        scope = "user:memberof:{}".format(authorg)
        if config['offline_access']:
            scope += ",offline_access"
        if config['scope']:
            scope += ",{}".format(config['scope'])
        params = dict(scope=scope)
        jwturl = "{}/v1/oauth/jwt?{}".format(ITSYOUONLINE, urlencode(params))
        headers = {"Authorization": "token {}".format(access_token)}
        response = requests.get(jwturl, headers=headers, verify=config['verify'])
        response.raise_for_status()
        session['iyo_jwt'] = response.text
    return redirect(on_complete_uri)


def _get_info(username, access_token=None, jwt=None):
    config = current_app.config["iyo_config"]
    if access_token:
        headers = {"Authorization": "token {}".format(access_token)}
    else:
        headers = {"Authorization": "Bearer {}".format(jwt)}
    userinfourl = "{}/api/users/{}/info".format(ITSYOUONLINE, username)
    response = requests.get(userinfourl, headers=headers, verify=config['verify'])
    response.raise_for_status()
    return response.json()




def get_auth_org2(org_from_request=False):
    config = current_app.config["iyo_config"]
    if org_from_request is True:
        return request.values[config['orgfromrequest']]

    return config['organization']


def requires_auth(org_from_request=False):
    def decorator(handler):
        """
        Wraps route handler to be only accessible after authentication via Itsyou.Online
        """

        @wraps(handler)
        def _wrapper(*args, **kwargs):
            if not session.get("_iyo_authenticated"):
                organization = get_auth_org2(org_from_request=org_from_request)
                config = current_app.config["iyo_config"]
                scopes = []
                scopes.append("user:memberof:{}".format(organization))
                if config["scope"]:
                    scopes.append(config['scope'])
                scope = ','.join(scopes)

                header = request.headers.get("Authorization")
                if header:
                    match = JWT_AUTH_HEADER.match(header)
                    if match:
                        jwt_string = match.group(1)
                        jwt_info = jwt.decode(jwt_string, ITSYOUONLINE_KEY)
                        jwt_scope = jwt_info["scope"]
                        if set(scope.split(",")).issubset(set(jwt_scope)):
                            username = jwt_info["username"]
                            session["iyo_user_info"] = _get_info(username, jwt=jwt_string)
                            session["_iyo_authenticated"] = time.time()
                            session['iyo_jwt'] = jwt_string
                            return handler(*args, **kwargs)
                    return "Could not authorize this request!", 403
                state = str(uuid.uuid4())
                session["_iyo_state"] = state
                session['_iyo_organization'] = organization
                session["_iyo_auth_complete_uri"] = request.full_path
                params = {
                    "response_type": "code",
                    "client_id": config["organization"],
                    "redirect_uri": config["callback_uri"],
                    "scope": scope,
                    "state" : state
                }
                base_url = "{}/v1/oauth/authorize?".format(ITSYOUONLINE)
                login_url = base_url + urlencode(params)
                return redirect(login_url)
            else:

                return handler(*args, **kwargs)
        return _wrapper
    return decorator

