from fastapi_jwt_auth.config import LoadConfig
from pydantic import ValidationError
from typing import Callable, List
from datetime import timedelta

class AuthConfig:
    _token = None
    _secret_key = None
    _public_key = None
    _private_key = None
    _algorithm = "HS256"
    _decode_algorithms = None
    _decode_leeway = 0
    _encode_issuer = None
    _decode_issuer = None
    _decode_audience = None
    _denylist_enabled = False
    _denylist_token_checks = {'access','refresh'}
    _header_name = "Authorization"
    _header_type = "Bearer"
    _token_in_denylist_callback = None
    _access_token_expires = timedelta(minutes=15)
    _refresh_token_expires = timedelta(days=30)

    @classmethod
    def load_config(cls, settings: Callable[...,List[tuple]]) -> "AuthConfig":
        try:
            config = LoadConfig(**{key.lower():value for key,value in settings()})

            cls._secret_key = config.authjwt_secret_key
            cls._public_key = config.authjwt_public_key
            cls._private_key = config.authjwt_private_key
            cls._algorithm = config.authjwt_algorithm
            cls._decode_algorithms = config.authjwt_decode_algorithms
            cls._decode_leeway = config.authjwt_decode_leeway
            cls._encode_issuer = config.authjwt_encode_issuer
            cls._decode_issuer = config.authjwt_decode_issuer
            cls._decode_audience = config.authjwt_decode_audience
            cls._denylist_enabled = config.authjwt_denylist_enabled
            cls._denylist_token_checks = config.authjwt_denylist_token_checks
            cls._header_name = config.authjwt_header_name
            cls._header_type = config.authjwt_header_type
            cls._access_token_expires = config.authjwt_access_token_expires
            cls._refresh_token_expires = config.authjwt_refresh_token_expires
        except ValidationError:
            raise
        except Exception:
            raise TypeError("Config must be pydantic 'BaseSettings' or list of tuple")

    @classmethod
    def token_in_denylist_loader(cls, callback: Callable[...,bool]) -> "AuthConfig":
        """
        This decorator sets the callback function that will be called when
        a protected endpoint is accessed and will check if the JWT has been
        been revoked. By default, this callback is not used.

        *HINT*: The callback must be a function that takes decrypted_token argument,
        args for object AuthJWT and this is not used, decrypted_token is decode
        JWT (python dictionary) and returns *`True`* if the token has been deny,
        or *`False`* otherwise.
        """
        cls._token_in_denylist_callback = callback
