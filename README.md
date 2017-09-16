# Flask-Itsyouonline

Flask-Itsyouonline is a plugin for Flask microframework implements the OAuth flow of itsyou.online 

## Configurations

- CLIENT_ID: itsyou.online client id.
- CLIENT_SECRET: client secret.
- REDIRECT_URI: your callback endpoint
- AUTH_ENDPOINT: from where to start the oauth flow
- ON_COMPLETE_ENDPOINT: make a post request to the end point with user informatin.


## Example application

```
import flask
from flask import Flask, 
from flask_itsyouonline import ItsyouonlineProvider

config = {
    'CLIENT_ID': 'flaskorg',
    'CLIENT_SECRET': 'CLIENTSECRET GOES HERE',
    'REDIRECT_URI' : 'https://37127c9e.ngrok.io/callback',
    'ORGANIZATION' : 'flaskorg',
    'AUTH_ENDPOINT': '/authorize',
    'CALLBACK_ENDPOINT': '/callback',
    'ON_COMPLETE_ENDPOINT': '/on_complete',
}
app = flask.Flask(__name__)
app.config.update(config)
itsapp = ItsyouonlineProvider()
itsapp.init_app(app)

@app.route("/on_complete", methods=["POST"])
def on_complete():
    print(request.form)

if __name__ == "__main__":

    app.run(debug=True, port=4000)

```

## Contributions
PRs are very welcome. 
