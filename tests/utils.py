from fastapi_jwt_auth import AuthJWT
from datetime import timedelta

def reset_config():
    AuthJWT._secret_key = None
    AuthJWT._algorithm = "HS256"
    AuthJWT._decode_leeway = 0
    AuthJWT._encode_issuer = None
    AuthJWT._decode_issuer = None
    AuthJWT._decode_audience = None
    AuthJWT._blacklist_enabled = None
    AuthJWT._blacklist_token_checks = []
    AuthJWT._token_in_blacklist_callback = None
    AuthJWT._access_token_expires = timedelta(minutes=15)
    AuthJWT._refresh_token_expires = timedelta(days=30)
