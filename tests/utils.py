import os
from fastapi_jwt_auth import AuthJWT
from datetime import timedelta

def reset_config():
    AuthJWT._access_token_expires = os.getenv("AUTHJWT_ACCESS_TOKEN_EXPIRES") or timedelta(minutes=15)
    AuthJWT._refresh_token_expires = os.getenv("AUTHJWT_REFRESH_TOKEN_EXPIRES") or timedelta(days=30)
    AuthJWT._blacklist_enabled = os.getenv("AUTHJWT_BLACKLIST_ENABLED") or None
    AuthJWT._secret_key = os.getenv("AUTHJWT_SECRET_KEY") or None
    AuthJWT._algorithm = os.getenv("AUTHJWT_ALGORITHM") or 'HS256'
    AuthJWT._token_in_blacklist_callback = None
