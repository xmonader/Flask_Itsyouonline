from flask_itsyouonline import configure, requires_auth
from flask import Flask

app = Flask(__name__)
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