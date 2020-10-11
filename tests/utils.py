from fastapi_jwt_auth import AuthJWT
from datetime import timedelta

def reset_config():
    AuthJWT._access_token_expires = timedelta(minutes=15)
    AuthJWT._refresh_token_expires = timedelta(days=30)
    AuthJWT._blacklist_enabled = None
    AuthJWT._secret_key = None
    AuthJWT._algorithm = "HS256"
    AuthJWT._token_in_blacklist_callback = None
