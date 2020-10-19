from fastapi_jwt_auth import AuthJWT
from datetime import timedelta

def reset_config():
    AuthJWT._secret_key = None
    AuthJWT._public_key = None
    AuthJWT._private_key = None
    AuthJWT._algorithm = "HS256"
    AuthJWT._decode_algorithms = None
    AuthJWT._decode_leeway = 0
    AuthJWT._encode_issuer = None
    AuthJWT._decode_issuer = None
    AuthJWT._decode_audience = None
    AuthJWT._denylist_enabled = None
    AuthJWT._denylist_token_checks = {'access','refresh'}
    AuthJWT._token_in_denylist_callback = None
    AuthJWT._header_name = "Authorization"
    AuthJWT._header_type = "Bearer"
    AuthJWT._access_token_expires = timedelta(minutes=15)
    AuthJWT._refresh_token_expires = timedelta(days=30)
