from pydantic import BaseModel, root_validator, validator
from typing import Optional, Union, Sequence
from types import GeneratorType
from datetime import timedelta

class LoadSettings(BaseModel):
    authjwt_access_token_expires: Optional[Union[int,timedelta]] = timedelta(minutes=15)
    authjwt_refresh_token_expires: Optional[Union[int,timedelta]] = timedelta(days=30)
    authjwt_decode_leeway: Optional[Union[int,timedelta]] = 0
    authjwt_blacklist_enabled: Optional[str] = None
    authjwt_blacklist_token_checks: Optional[Sequence[str]] = []
    authjwt_secret_key: Optional[str] = None
    authjwt_algorithm: Optional[str] = "HS256"

    @root_validator(pre=True)
    def validate_blacklist_enabled(cls, values):
        _access_token_expires = values.get("authjwt_access_token_expires")
        _refresh_token_expires = values.get("authjwt_refresh_token_expires")
        _decode_leeway = values.get("authjwt_decode_leeway")
        _blacklist_enabled = values.get("authjwt_blacklist_enabled")
        _blacklist_token_checks = values.get("authjwt_blacklist_token_checks")
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

        if (
            _blacklist_token_checks and
            not isinstance(_blacklist_token_checks, (list, tuple, set, frozenset, GeneratorType))
        ):
            raise TypeError("The 'AUTHJWT_BLACKLIST_TOKEN_CHECKS' must be a sequence")

        if _secret_key and not isinstance(_secret_key, str):
            raise TypeError("The 'AUTHJWT_SECRET_KEY' must be a string")

        if _algorithm and not isinstance(_algorithm, str):
            raise TypeError("The 'AUTHJWT_ALGORITHM' must be a string")

        return values

    @validator('authjwt_blacklist_token_checks', each_item=True)
    def validate_blacklist_token_checks(cls, v):
        if v not in ['access','refresh']:
            raise ValueError("The 'AUTHJWT_BLACKLIST_TOKEN_CHECKS' must be between 'access' or 'refresh'")

        return v

    class Config:
        min_anystr_length = 1
        anystr_strip_whitespace = True
