from pydantic import BaseModel, root_validator
from typing import Optional, Union
from datetime import timedelta

class LoadSettings(BaseModel):
    authjwt_access_token_expires: Optional[Union[int,timedelta]] = timedelta(minutes=15)
    authjwt_refresh_token_expires: Optional[Union[int,timedelta]] = timedelta(days=30)
    authjwt_decode_leeway: Optional[Union[int,timedelta]] = 0
    authjwt_blacklist_enabled: Optional[str] = None
    authjwt_secret_key: Optional[str] = None
    authjwt_algorithm: Optional[str] = "HS256"

    @root_validator(pre=True)
    def validate_blacklist_enabled(cls, values):
        _access_token_expires = values.get("authjwt_access_token_expires")
        _refresh_token_expires = values.get("authjwt_refresh_token_expires")
        _decode_leeway = values.get("authjwt_decode_leeway")
        _blacklist_enabled = values.get("authjwt_blacklist_enabled")
        _secret_key = values.get("authjwt_secret_key")
        _algorithm = values.get("authjwt_algorithm")

        if _access_token_expires and not isinstance(_access_token_expires, (timedelta, int)):
            raise TypeError("The 'AUTHJWT_ACCESS_TOKEN_EXPIRES' must be a timedelta or integer")

        if _refresh_token_expires and not isinstance(_refresh_token_expires, (timedelta, int)):
            raise TypeError("The 'AUTHJWT_REFRESH_TOKEN_EXPIRES' must be a timedelta or integer")

        if _decode_leeway and not isinstance(_decode_leeway, (timedelta, int)):
            raise TypeError("The 'AUTHJWT_DECODE_LEEWAY' must be a timedelta or integer")

        if _blacklist_enabled and _blacklist_enabled not in ['true','false']:
            raise TypeError("The 'AUTHJWT_BLACKLIST_ENABLED' must be between 'true' or 'false'")

        if _secret_key and not isinstance(_secret_key, str):
            raise TypeError("The 'AUTHJWT_SECRET_KEY' must be an string")

        if _algorithm and not isinstance(_algorithm, str):
            raise TypeError("The 'AUTHJWT_ALGORITHM' must be an string")

        return values

    class Config:
        min_anystr_length = 1
        anystr_strip_whitespace = True
