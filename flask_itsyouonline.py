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

ITSYOUONLINEV1 = "https://itsyou.online/v1"
JWT_AUTH_HEADER = re.compile("^bearer (.*)$", re.IGNORECASE)
ITSYOUONLINE_KEY = """-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAES5X8XrfKdx9gYayFITc89wad4usrk0n2
7MjiGYvqalizeSWTHEpnd7oea9IQ8T5oJjMVH5cc0H5tFSKilFFeh//wngxIyny6
6+Vq5t5B0V0Ehy01+2ceEon2Y0XDkIKv
-----END PUBLIC KEY-----"""


def _invalidate_session():
    authenticated_ = session.get('_iyo_authenticated')
    if not authenticated_ or authenticated_ + 300 < time.time():
        if '_iyo_authenticated' in session:
            del session['_iyo_authenticated']
        if 'iyo_user_info' in session:
            del session['iyo_user_info']
        if 'iyo_jwt' in session:
            del session['iyo_jwt']


def configure(app, organization, client_secret, callback_uri, callback_route, scope=None):
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
    """
    app.before_request(_invalidate_session)
    app.config['iyo_config'] = dict(organization=organization, client_secret=client_secret,
                                    callback_uri=callback_uri, callback_route=callback_route,
                                    scope=scope)
    app.add_url_rule(callback_route, '_callback', _callback)


def authenticated(handler):
    """
    Wraps route handler to be only accessible after authentication via Itsyou.Online
    """
    @wraps(handler)
    def _wrapper(*args, **kwargs):
        if not session.get("_iyo_authenticated"):
            config = current_app.config["iyo_config"]
            scope = "user:memberof:%s" % config["organization"]
            if config["scope"]:
                scope = "%s,%s" % (scope, config["scope"])
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
                        return handler(*args, **kwargs)
                return "Could not authorize this request!", 403
            state = str(uuid.uuid4())
            session["_iyo_state"] = state
            session["_iyo_auth_complete_uri"] = request.path
            params = {
                "response_type": "code",
                "client_id": config["organization"],
                "redirect_uri": config["callback_uri"],
                "scope": scope,
                "state" : state
            }
            base_url = "{}/oauth/authorize?".format(ITSYOUONLINEV1)
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
    params = {
        "code" : code,
        "state": state,
        "grant_type": "authorization_code",
        "client_id" : organization,
        "client_secret": config["client_secret"],
        "redirect_uri": config["callback_uri"],
    }
    base_url = "{}/oauth/access_token?".format(ITSYOUONLINEV1)
    url = base_url + urlencode(params)
    response = requests.post(url)
    response.raise_for_status()
    response = response.json()
    scope_parts = response["scope"].split(",")
    if not "user:memberof:%s" % organization in scope_parts:
        return "User is not authorized.", 403
    access_token = response["access_token"]
    username = response["info"]["username"]
    # Get user info
    session['iyo_user_info'] = _get_info(username, access_token=access_token)
    session['_iyo_authenticated'] = time.time()
    return redirect(on_complete_uri)


def _get_info(username, access_token=None, jwt=None):
    if access_token:
        headers = {"Authorization": "token %s" % access_token}
    else:
        headers = {"Authorization": "Bearer %s" % jwt}
    userinfourl = "https://itsyou.online/api/users/%s/info" % username
    response = requests.get(userinfourl, headers=headers)
    response.raise_for_status()
    return response.json()
