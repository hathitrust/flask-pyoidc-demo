from contextlib import contextmanager
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata
from flask_pyoidc.user_session import UserSession
from os import getenv
import flask
import json
import logging
import secrets

load_dotenv()

app = Flask(__name__)
app.config.update({
        'OIDC_REDIRECT_URI': 'http://127.0.0.1:5555/callback',
        'SECRET_KEY': getenv('FLASK_SECRET_KEY')
        })

client_metadata = ClientMetadata(
        client_id=getenv('OIDC_CLIENT_ID'),
        client_secret=getenv('OIDC_CLIENT_SECRET')
        )

provider_config = ProviderConfiguration(getenv('OIDC_ISSUER'),
                                        client_metadata=client_metadata,
                                        auth_request_params={'scope': ['openid','email','groups','profile']})

auth = OIDCAuthentication({'default': provider_config}, app)

@contextmanager
def users_json():
    try:
        with open('users.json','r') as file:
            userinfo = json.load(file)
        if 'users' not in userinfo:
            userinfo['users'] = {}
        if 'registrations' not in userinfo:
            userinfo['registrations'] = {}
        yield userinfo
        with open('users.json','w') as file:
            json.dump(userinfo,file,indent=2)
    finally:
        pass

@app.route('/onboard')
# TODO only logged-in 'superusers' should be able to use this route
def onboard():
    with users_json() as userinfo:

        email = request.args.get('email')
        reg_key = secrets.token_urlsafe(30)

        userinfo['registrations'][email] = reg_key

    return jsonify({'registration_url': f"http://127.0.0.1:5555/register?email={email}&reg_key={reg_key}"})

@app.route('/register')
@auth.oidc_auth('default')
def register():
    user_session = UserSession(flask.session)
    email = request.args.get('email')
    reg_key = request.args.get('reg_key')

    # does reg key param match? if so save sub
    with users_json() as userinfo:
        if reg_key and email and email in userinfo['registrations'] and userinfo['registrations'][email] == reg_key:
            userinfo['users'][user_session.id_token['sub']] = email
            userinfo['registrations'].pop(email)
            return jsonify(user_session.id_token)
        else:
            flask.abort(401)

@app.route('/')
@auth.oidc_auth('default')
def index():
    user_session = UserSession(flask.session)
    with open('users.json','r') as file:
        userinfo = json.load(file)

    sub = user_session.id_token['sub']
    if(sub in userinfo['users']):
        return jsonify({ "email": userinfo['users'][sub], "id_token": user_session.id_token})
    else:
        flask.abort(401)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    auth.init_app(app)
    app.run(port=5555,debug=True)
