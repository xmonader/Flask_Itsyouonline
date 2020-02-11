# Flask-Itsyouonline

Flask-Itsyouonline is a plugin for Flask microframework implements the OAuth flow of itsyou.online 

## Installation
`pip3 install flask_itsyouonline`

## Configurations

- CLIENT_ID: itsyou.online client id.
- CLIENT_SECRET: client secret.
- REDIRECT_URI: your callback endpoint
- AUTH_ENDPOINT: from where to start the oauth flow
- ON_COMPLETE_ENDPOINT: make a post request to the end point with user information.


## Example application

```python
import flask
from flask import Flask
from flask_itsyouonline import configure, authenticated

app = flask.Flask(__name__)
# flask_itsyouonline uses sessions secret needs to be set
app.secret_key = b'_5#y2l"F4q8z\n\xec]/'

configure(app, 'Itsyou.Online organization', 'Itsyou.Online client secret', 
          "http://127.0.0.1/callback", '/callback', 'user:publickey:ssh')

@app.route("/", methods=["GET"])
@authenticated
def home():
    return "Hello %s" % flask.session['iyo_user_info']['username']

if __name__ == "__main__":

    app.run(debug=True, port=4000)

```

## Another example

```python
from flask_itsyouonline import configure, requires_auth
from flask import Flask

app = Flask(__name__)
# flask_itsyouonline uses sessions secret needs to be set
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

configure(app, 'flaskitsyou', 'ibSuQCgP-_CV8XzlPi0oZucEGCTTxTmffv8YMjQzLgxOFqaoGh00', 
          "http://127.0.0.1:5000/callback", '/callback', None, True, True)


@app.route("/hello", methods=["GET"])
def hello():
    return "Hello, World"

@app.route("/iyohello", methods=["GET"])
@requires_auth()
def iyohello():
    return "Hello, World authorized"


app.run()
```


## Contributions
PRs are very welcome. 
