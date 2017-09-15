import uuid, requests
from urllib.parse import urlparse, parse_qs, urlencode
from urllib.request import urlopen
import flask
from flask import Flask, send_from_directory, render_template, request, jsonify, redirect,url_for
__version__ = '0.0.1'

# jwt flow is copied from codescalers dashboard project.
def make_oauth_route(**kwargs):
    def make_oauth():
        id = request.args.get('id')
        def login_to_idserver():
            from uuid import uuid4
            STATE = str(uuid4())
            SCOPE = "user:memberof:"+kwargs['ORGANIZATION']
            params = {
                "response_type": "code",
                "client_id":kwargs['CLIENT_ID'],
                "redirect_uri":kwargs['REDIRECT_URI'],
                "scope": SCOPE,
                "state" : STATE
            }
            base_url = "https://itsyou.online/v1/oauth/authorize?"
            url = base_url + urlencode(params)
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
            def get_access_token():
                params = {
                "code" : code,
                "state":state,
                "redirect_uri": kwargs['REDIRECT_URI'],
                # "grant_type": "authorization_code",
                "client_id" : kwargs['CLIENT_ID'],
                "client_secret": kwargs['CLIENT_SECRET']
                }
                base_url = "https://itsyou.online/v1/oauth/access_token?"
                url = base_url + urlencode(params)
                response = requests.post(url)
                response.raise_for_status()
                response = response.json()
                print(response)
                if ("user:memberof:"+kwargs['ORGANIZATION']) in response['scope'].split(','):
                    access_token = response['access_token']
                    return access_token
                else:
                    return None
            def get_jwt(access_token):
                base_url = "https://itsyou.online/v1/oauth/jwt"
                headers = {'Authorization': 'token %s' % access_token}
                data = {'scope': 'user:memberOf:%s' % kwargs['CLIENT_ID']}
                response = requests.post(base_url, json=data, headers=headers, verify=False)
                return response.content.decode()
            access_token = get_access_token()
            print(access_token)
            if access_token:
                jwt = get_jwt(access_token)
            print(jwt)
            return jwt
        return False
    return get_code


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
        self.callbackendpoint = app.config['CALLBACKENDPOINT']

        oauth_route_function = make_oauth_route(**app.config)
        # import ipdb; ipdb.set_trace()
        app.route(self.authendpoint)(oauth_route_function)
        callback_route_function = make_callback_route(**app.config)
        app.route(self.callbackendpoint)(callback_route_function)

        return app
