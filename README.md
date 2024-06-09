SOGIS my.so.ch Authentication
=============================

Authenticates through a my.so.ch JWE token.

The service will decrypt/decode the JWE, then:

1. Check whether the `iss` claim of the token matches one of the configured `allowed_iss`
2. Extract the userid from the claims (first non-empty claim of the configured `userid_claims`)
3. Validate whether the userid exists using the configured `userid_verify_sql` query.
4. Issue a JWT for QWC

Configuration
-------------

See [sogis-mysoch-auth.json](./schemas/sogis-mysoch-auth.json) configuration schema.

All configuration options can also be set with the respective UPPER_CASE environment variables.

Usage/Development
-----------------

Create and activate a virtual environment:

    python3 -m venv .venv
    source .venv/bin/activate

Install requirements:

    pip install -r requirements.txt

### Usage

Run standalone application:

    python src/server.py
