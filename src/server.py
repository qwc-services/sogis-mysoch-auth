import json
import logging
import os
import sys
from datetime import datetime
from time import time
from base64 import b64decode, urlsafe_b64encode
from flask import Flask, jsonify, request, abort, make_response, redirect
from flask_jwt_extended import create_access_token, set_access_cookies, unset_jwt_cookies
from jwcrypto.jwe import JWE
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT
from sqlalchemy.sql import text as sql_text
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse, unquote

from qwc_services_core.auth import auth_manager, optional_auth, get_identity
from qwc_services_core.database import DatabaseEngine
from qwc_services_core.runtime_config import RuntimeConfig
from qwc_services_core.tenant_handler import (
    TenantHandler, TenantPrefixMiddleware, TenantSessionInterface)


app = Flask(__name__)

app.config['JWT_COOKIE_SECURE'] = os.environ.get(
    'JWT_COOKIE_SECURE', 'False').lower() == 'true'
app.config['JWT_COOKIE_SAMESITE'] = os.environ.get(
    'JWT_COOKIE_SAMESITE', 'Lax')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = int(os.environ.get(
    'JWT_ACCESS_TOKEN_EXPIRES', 12*3600))

jwt = auth_manager(app)
app.secret_key = app.config['JWT_SECRET_KEY']


tenant_handler = TenantHandler(app.logger)

app.wsgi_app = TenantPrefixMiddleware(app.wsgi_app)
app.session_interface = TenantSessionInterface(os.environ)

class ExpiringSet():
    def __init__(self, max_age_seconds):
        self.age = max_age_seconds
        self.container = {}

    def contains(self, value):
        if value not in self.container:
            return False
        if time() - self.container[value] > self.age:
            del self.container[value]
            return False

        return True

    def add(self, value):
        self.container[value] = time()

prev_tokens = ExpiringSet(120)



@app.route('/login', methods=['GET'])
def login():
    config_handler = RuntimeConfig("mysochAuth", app.logger)
    tenant = tenant_handler.tenant()
    config = config_handler.tenant_config(tenant)

    # Request args
    token = request.args.get('token')
    target_url = request.args.get('url')
    if not token:
        app.logger.info("login: No token specified")
        abort(400, "No token specified")

    if not target_url:
        app.logger.info("login: No redirect URL")
        abort(400, "No redirect URL")

    if prev_tokens.contains(token):
        app.logger.info("login: Token already used")
        abort(400, "Token already used")
    prev_tokens.add(token)

    # Decode JWE
    jwe_secret = urlsafe_b64encode(config.get("jwe_secret", "").encode()).decode()
    jwt_secret = urlsafe_b64encode(config.get("jwt_secret", "").encode()).decode()

    jwe_key = JWK.from_json('{"kty" : "oct", "k": "%s"}' % jwe_secret)
    jwt_key = JWK.from_json('{"kty": "oct", "k": "%s"}' % jwt_secret)
    app.logger.debug("JWE key: %s" % jwe_key.export())
    app.logger.debug("JWT key: %s" % jwt_key.export())

    jwe = JWE()
    try:
        jwe.deserialize(token, jwe_key)
    except:
        abort(400, "Token decryption failed")

    # Validate JWE header
    app.logger.debug("JWE header: %s" % jwe.jose_header)
    if jwe.jose_header.get('alg') != 'dir':
        app.logger.info("login: Bad value for JWE alg")
        abort(400)
    if jwe.jose_header.get('enc') not in ['A128CBC-HS256', 'A256CBC-HS512']:
        app.logger.info("login: Bad value for JWE enc")
        abort(400)
    if jwe.jose_header.get('typ') != 'JWT':
        app.logger.info("login: Bad value for JWE typ")
        abort(400)
    if jwe.jose_header.get('cty') != 'JWT':
        app.logger.info("login: Bad value for JWE cty")
        abort(400)

    # Verify and decode JWT
    jwt = JWT()
    # jwt.leeway = 100000000000000 # NOTE Testing only
    try:
        jwt.deserialize(jwe.payload.decode(), jwt_key)
    except Exception as e:
        app.logger.debug("Token validation failed: %s" % str(e))
        abort(400, "Token validation failed")

    # Validate JWT header
    app.logger.debug("JWT header: %s" % jwt.header)
    jwt_header = json.loads(jwt.header)
    if jwt_header.get('alg') != 'HS256':
        app.logger.info("login: Bad value for JWT alg")
        abort(400)
    if jwt_header.get('typ') != 'JWT':
        app.logger.info("login: Bad value for JWT typ")
        abort(400)

    # Extract and validate JWT claims
    claims = json.loads(jwt.claims)

    app.logger.debug("Decoded claims %s" % jwt.claims)

    # Verify iat and duration
    if not claims.get("iat", None) or claims["iat"] > datetime.now().timestamp():
        app.logger.info("login: Bad value for JWT claim iat")
        abort(400)

    if claims['exp'] - claims['nbf'] > config.get("max_token_duration", 60):
        app.logger.info("login: Bad JWT token duration'")
        abort(400)

    # Verify ISS
    if claims["iss"] not in config.get("allowed_iss", []):
        app.logger.info("login: Bad value for JWT claim iss")
        abort(400)

    # Database
    db_url = config.get('db_url')
    db_engine = DatabaseEngine()
    db = db_engine.db_engine(db_url)

    # Verify login
    userid = next(claims[userid_claim] for userid_claim in config.get("userid_claims", []) if claims.get(userid_claim))
    toarray = lambda x: [x] if isinstance(x, str) else x
    displayname = next((
        " ".join(list(map(lambda x: claims.get(x), toarray(displayname_claim))))
        for displayname_claim in config.get("displayname_claims", [])
        if False not in list(map(lambda x: bool(claims.get(x)), toarray(displayname_claim)))), ""
    )
    app.logger.debug("userid: %s, displayname: %s" % (userid, displayname))

    user_exists = False
    with db.connect() as connection:

        sql = sql_text(config.get("userid_verify_sql", ""))
        result = connection.execute(sql, {"id": userid})
        user_exists = result.first() is not None

    parts = urlparse(target_url)
    target_query = dict(parse_qsl(parts.query))

    if user_exists:
        identity = {
            'username': userid,
            'user_infos': {
                'mysoch': True,
                'displayname': displayname
            },
            'autologin': True
        }
        tenant_header_name = config.get("tenant_header_name", "")
        tenant_header_value = config.get("tenant_header_value", "")
        access_token = create_access_token(identity=identity)
        if tenant_header_name:
            target_query.update({'config:tenant': tenant_header_name + "=" + tenant_header_value})
        target_query.update({'config:autologin': 1})
        parts = parts._replace(query=urlencode(target_query))
        target_url = urlunparse(parts)
        resp = make_response(redirect(target_url))
        if tenant_header_name:
            app.logger.debug("Setting header %s=%s" % (tenant_header_name, tenant_header_value))
            resp.headers[tenant_header_name] = tenant_header_value
        set_access_cookies(resp, access_token)
        return resp
    else:
        target_query.update({'mysoch:unknownidentity': 1})

    parts = parts._replace(query=urlencode(target_query))
    target_url = urlunparse(parts)
    return make_response(redirect(target_url))

@app.route('/checklogin', methods=['GET'])
@optional_auth
def checklogin():
    config_handler = RuntimeConfig("mysochAuth", app.logger)
    tenant = tenant_handler.tenant()
    config = config_handler.tenant_config(tenant)

    identity = get_identity()
    target_url = request.args.get('url')
    if isinstance(identity, dict) and identity.get("user_infos", {}).get("mysoch", False):
        tenant_header_name = config.get("tenant_header_name", "")
        tenant_header_value = config.get("tenant_header_value", "")
        parts = urlparse(target_url)
        target_query = dict(parse_qsl(parts.query))
        if tenant_header_name:
            target_query.update({'config:tenant': tenant_header_name + "=" + tenant_header_value})
        target_query.update({'config:autologin': 1})
        parts = parts._replace(query=urlencode(target_query))
        target_url = urlunparse(parts)
        resp = make_response(redirect(target_url))
        print(tenant_header_name + "=" + tenant_header_value)
        if tenant_header_name:
            app.logger.debug("Setting header %s=%s" % (tenant_header_name, tenant_header_value))
            resp.headers[tenant_header_name] = tenant_header_value
        return resp
    else:
        resp = make_response(redirect(target_url))
        if identity:
            unset_jwt_cookies(resp)
        return resp

@app.route('/logout', methods=['GET'])
@optional_auth
def logout():
    target_url = request.args.get('url')
    identity = get_identity()
    resp = make_response(redirect(target_url))
    if identity:
        unset_jwt_cookies(resp)
    return resp

@app.route("/ready", methods=['GET'])
def ready():
    """ readyness probe endpoint """
    return jsonify({"status": "OK"})


@app.route("/healthz", methods=['GET'])
def healthz():
    """ liveness probe endpoint """
    return jsonify({"status": "OK"})


if __name__ == '__main__':
    app.logger.setLevel(logging.DEBUG)
    app.run(host='localhost', port=5024, debug=True)
