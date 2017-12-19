import uuid, requests
from urllib.parse import urlparse, parse_qs, urlencode
from urllib.request import urlopen
import flask
import time
from flask import Flask, send_from_directory, render_template, request, jsonify, redirect, url_for, session

__version__ = '0.0.1'

# jwt flow is copied from codescalers dashboard project.

ITSYOUONLINEV1 = "https://itsyou.online/v1"
def make_oauth_route(**kwargs):
    def make_oauth():
        if 'iyo_user_info' in session:
            endpoint = kwargs.get('ON_COMPLETE_ENDPOINT', None)
            if endpoint is not None:
                return redirect(endpoint)
        
        id = request.args.get('id')
        def login_to_idserver():
            from uuid import uuid4
            STATE = str(uuid4())
            SCOPE = "user:memberof:"+kwargs['ORGANIZATION']
            if "SCOPE" in kwargs:
                SCOPE += "," + kwargs['SCOPE']
            params = {
                "response_type": "code",
                "client_id":kwargs['CLIENT_ID'],
                "redirect_uri":kwargs['REDIRECT_URI'],
                "scope": SCOPE,
                "state" : STATE
            }
            base_url = "{}/oauth/authorize?".format(ITSYOUONLINEV1)
            url = base_url + urlencode(params)
            print("url: ", url)
            return url
        login_url = login_to_idserver()
        return redirect(login_url)
    return make_oauth

def make_callback_route(**kwargs):
    def get_code():
        code = request.args.get("code")
        state = request.args.get("state")
        if code :
            #get the access token
            def get_access_token_and_username():
                params = {
                    "code" : code,
                    "state": state,
                    "redirect_uri": kwargs['REDIRECT_URI'],
                    "grant_type": "authorization_code",
                    "client_id" : kwargs['CLIENT_ID'],
                    "client_secret": kwargs['CLIENT_SECRET']
                }
                url = "{}/oauth/access_token".format(ITSYOUONLINEV1)
                response = requests.post(url, params=params)
                response.raise_for_status()
                response = response.json()
                if ("user:memberof:"+kwargs['ORGANIZATION']) in response['scope'].split(','):
                    access_token = response['access_token']
                    print(response)
                    username = response['info']['username']
                    scope = response['scope']
                    return access_token, username
                else:
                    return None, None

            def get_jwt(access_token):
                base_url = "{}/oauth/jwt".format(ITSYOUONLINEV1)
                headers = {'Authorization': 'token %s' % access_token}
                data = {'scope': 'user:memberOf:%s' % kwargs['CLIENT_ID']}
                response = requests.post(base_url, json=data, headers=headers, verify=False)
                return response.content.decode()
            access_token, username = get_access_token_and_username()
            if access_token:
                jwt = get_jwt(access_token)
                headers = {'Authorization': 'bearer {}'.format(jwt)}
                userinfourl = "https://itsyou.online/api/users/{}/info".format(username)
                response = requests.get(userinfourl, headers=headers) 
                response.raise_for_status()
                session['_iyo_authenticated'] = time.time()
                session['iyo_user_info'] = response.json()
                session['iyo_jwt'] = jwt
                endpoint = kwargs.get('ON_COMPLETE_ENDPOINT', None)
                if endpoint is not None:
                    return redirect(endpoint)
        return False
    return get_code


def invalidate_session():
    authenticated = session.get('_iyo_authenticated')
    if not authenticated or authenticated + 300 < time.time():
        if '_iyo_authenticated' in session:
            del session['_iyo_authenticated']
        if 'iyo_user_info' in session:
            del session['iyo_user_info']
        if 'iyo_jwt' in session:
            del session['iyo_jwt']


class ItsyouonlineProvider(object):

    def __init__(self, app=None, **defaults):

        if app:
            self.init_app(app)

    def init_app(self, app):
        """
        Install authorize and callback routes on the application.

        :param app: a :class:`flask.Flask` instance.
        """
        self.client_id = app.config['CLIENT_ID']
        self.client_secret = app.config['CLIENT_SECRET']
        self.redirect_uri = app.config['REDIRECT_URI']
        self.organization = app.config['ORGANIZATION']
        self.authendpoint = app.config['AUTH_ENDPOINT']
        self.callbackendpoint = app.config['CALLBACK_ENDPOINT']
        self.oncompleteendpoint = app.config.get('ON_COMPLETE_ENDPOINT', '')

        oauth_route_function = make_oauth_route(**app.config)
        # import ipdb; ipdb.set_trace()
        app.route(self.authendpoint)(oauth_route_function)
        callback_route_function = make_callback_route(**app.config)
        app.route(self.callbackendpoint)(callback_route_function)

        app.before_request(invalidate_session)

        return app
