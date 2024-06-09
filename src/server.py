import json
import logging
import os
import sys
import time
from base64 import b64decode, urlsafe_b64encode
from flask import Flask, jsonify, request, abort, make_response, redirect
from flask_jwt_extended import create_access_token, set_access_cookies
from jwcrypto.jwe import JWE
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT
from sqlalchemy.sql import text as sql_text
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse, unquote

from qwc_services_core.database import DatabaseEngine
from qwc_services_core.jwt import jwt_manager
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

jwt = jwt_manager(app)
app.secret_key = app.config['JWT_SECRET_KEY']


tenant_handler = TenantHandler(app.logger)

app.wsgi_app = TenantPrefixMiddleware(app.wsgi_app)
app.session_interface = TenantSessionInterface(os.environ)


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

    # Verify and decode JWT
    jwt = JWT()
    # jwt.leeway = 100000000000000 # NOTE Testing only
    try:
        jwt.deserialize(jwe.payload.decode(), jwt_key)
    except Exception as e:
        app.logger.debug("Token validation failed: %s" % str(e))
        abort(400, "Token validation failed")

    claims = json.loads(jwt.claims)

    app.logger.debug("Decoded claims %s" % jwt.claims)

    # Verify ISS
    if claims["iss"] not in config.get("allowed_iss", []):
        app.logger.info("login: Bad value for iss")
        abort(400)

    # Verify exp
    if claims["exp"] >= round(time.time()):
        app.logger.info("login: Token expired")
        abort(400)

    # Database
    db_url = config.get('db_url')
    db_engine = DatabaseEngine()
    db = db_engine.db_engine(db_url)

    # Verify login

    userid = next(claims[userid_claim] for userid_claim in config.get("userid_claims", []) if claims.get(userid_claim))
    displayname = next(claims[displayname_claim] for displayname_claim in config.get("displayname_claims", []) if claims.get(displayname_claim))
    app.logger.debug("userid: %s, displayname: %s" % (userid, displayname))

    user_exists = False
    with db.connect() as connection:

        sql = sql_text(config.get("userid_verify_sql", ""))
        result = connection.execute(sql, {"id": userid})
        user_exists = result.first() is not None

    if user_exists:
        identity = {
            'username': userid,
            'user_infos': {
                'displayname': displayname,
                'mysoch': True
            },
            'autologin': True
        }
        access_token = create_access_token(identity=identity)
        resp = make_response(redirect(target_url))
        set_access_cookies(resp, access_token)
        return resp
    else:
        parts = urlparse(target_url)
        target_query = dict(parse_qsl(parts.query))
        target_query.update({'mysoch:unknownidentity': 1})
        parts = parts._replace(query=urlencode(target_query))
        target_url = urlunparse(parts)
        return make_response(redirect(target_url))


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
