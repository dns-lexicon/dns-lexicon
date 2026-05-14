transip
    * `auth_username` specify username for authentication

    * `auth_api_key` specify the private key to use for API authentication, in PEM format: can be either the path of the key file (eg. /tmp/key.pem) or the base64 encoded content of this file prefixed by 'base64::' (eg. base64::eyJhbGciOyJ...)

    * `auth_key_is_global` set this flag is the private key used is a global key with no IP whitelist restriction
