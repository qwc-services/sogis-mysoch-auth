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

The static config files are stored as JSON files in `$CONFIG_PATH` with subdirectories for each tenant,
e.g. `$CONFIG_PATH/default/*.json`. The default tenant name is `default`.

### MySoCH Service config

* [JSON schema](schemas/sogis-mysoch-auth.json)
* File location: `$CONFIG_PATH/<tenant>/mysochAuthConfig.json`

Example:

```json
  "config": {
    "db_url": "postgresql:///?service=qwc_testdb",
    "jwe_secret": "<jwe_secret>",
    "jwt_secret": "<jwt_secret>"
  }
```
### Environment variables

Config options in the config file can be overridden by equivalent uppercase environment variables.

Run locally
-----------

Install dependencies and run:

    export CONFIG_PATH=<CONFIG_PATH>
    uv run src/server.py

To use configs from a `qwc-docker` setup, set `CONFIG_PATH=<...>/qwc-docker/volumes/config`.

Set `FLASK_DEBUG=1` for additional debug output.

Set `FLASK_RUN_PORT=<port>` to change the default port (default: `5000`).

Docker usage
------------

The Docker image is published on [Dockerhub](https://hub.docker.com/r/sourcepole/sogis-mysoch-auth).

See sample [docker-compose.yml](https://github.com/qwc-services/qwc-docker/blob/master/docker-compose-example.yml) of [qwc-docker](https://github.com/qwc-services/qwc-docker).
