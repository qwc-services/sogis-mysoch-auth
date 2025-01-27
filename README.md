SOGIS my.so.ch Authentication
=============================

Authenticates through a my.so.ch JWE token.

The service will decrypt/decode the JWE, then:

1. Check whether the `iss` claim of the token matches one of the configured `allowed_iss`
2. Extract the userid from the claims (first non-empty claim of the configured `userid_claims`)
3. Validate whether the userid exists using the configured `userid_verify_sql` query, or check whether the userid shall be autoregistered using `autoregistration_allowed_query` and `autoregistration_query`.
4. Issue a JWT for QWC

Configuration
-------------

See [sogis-mysoch-auth.json](./schemas/sogis-mysoch-auth.json) configuration schema.

All configuration options can also be set with the respective UPPER_CASE environment variables.

Development
-----------

Install dependencies and run service:

    uv run src/server.py

With config path:

    CONFIG_PATH=/PATH/TO/CONFIGS/ uv run src/server.py
