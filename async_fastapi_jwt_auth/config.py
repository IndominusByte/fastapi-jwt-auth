from datetime import timedelta
from typing import List, Optional, Sequence, Set, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    StrictBool,
    StrictInt,
    StrictStr,
    field_validator,
    validator,
)
from pydantic.functional_validators import AfterValidator
from typing_extensions import Annotated


def validate_token_location(v):
    if v not in ["headers", "cookies"]:
        raise ValueError(
            "The 'authjwt_token_location' must be between 'headers' or 'cookies'"
        )
    return v


def validate_denylist_token_checks(v):
    if v not in ["access", "refresh"]:
        raise ValueError(
            "The 'authjwt_denylist_token_checks' must be between 'access' or 'refresh'"
        )
    return v


def validate_csrf_methods(v):
    if v.upper() not in {"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"}:
        raise ValueError(
            "The 'authjwt_csrf_methods' must be between http request methods"
        )
    return v.upper()


TokenLocation = Annotated[StrictStr, AfterValidator(validate_token_location)]
DenyListTokenChecks = Annotated[
    StrictStr, AfterValidator(validate_denylist_token_checks)
]
CsrfMethod = Annotated[StrictStr, AfterValidator(validate_csrf_methods)]


class LoadConfig(BaseModel):
    authjwt_token_location: Optional[Union[Set[TokenLocation], List[TokenLocation]]] = {
        "headers"
    }
    authjwt_secret_key: Optional[StrictStr] = None
    authjwt_public_key: Optional[StrictStr] = None
    authjwt_private_key: Optional[StrictStr] = None
    authjwt_algorithm: Optional[StrictStr] = "HS256"
    authjwt_decode_algorithms: Optional[List[StrictStr]] = None
    authjwt_decode_leeway: Optional[Union[StrictInt, timedelta]] = 0
    authjwt_encode_issuer: Optional[StrictStr] = None
    authjwt_decode_issuer: Optional[StrictStr] = None
    authjwt_decode_audience: Optional[
        Union[StrictStr, Set[StrictStr], List[StrictStr]]
    ] = None
    authjwt_denylist_enabled: Optional[StrictBool] = False
    authjwt_denylist_token_checks: Optional[
        Union[Set[DenyListTokenChecks], List[DenyListTokenChecks]]
    ] = {"access", "refresh"}
    authjwt_header_name: Optional[StrictStr] = "Authorization"
    authjwt_header_type: Optional[StrictStr] = "Bearer"
    authjwt_access_token_expires: Optional[
        Union[StrictBool, StrictInt, timedelta]
    ] = timedelta(minutes=15)
    authjwt_refresh_token_expires: Optional[
        Union[StrictBool, StrictInt, timedelta]
    ] = timedelta(days=30)
    # option for create cookies
    authjwt_access_cookie_key: Optional[StrictStr] = "access_token_cookie"
    authjwt_refresh_cookie_key: Optional[StrictStr] = "refresh_token_cookie"
    authjwt_access_cookie_path: Optional[StrictStr] = "/"
    authjwt_refresh_cookie_path: Optional[StrictStr] = "/"
    authjwt_cookie_max_age: Optional[StrictInt] = None
    authjwt_cookie_domain: Optional[StrictStr] = None
    authjwt_cookie_secure: Optional[StrictBool] = False
    authjwt_cookie_samesite: Optional[StrictStr] = None
    # option for double submit csrf protection
    authjwt_cookie_csrf_protect: Optional[StrictBool] = True
    authjwt_access_csrf_cookie_key: Optional[StrictStr] = "csrf_access_token"
    authjwt_refresh_csrf_cookie_key: Optional[StrictStr] = "csrf_refresh_token"
    authjwt_access_csrf_cookie_path: Optional[StrictStr] = "/"
    authjwt_refresh_csrf_cookie_path: Optional[StrictStr] = "/"
    authjwt_access_csrf_header_name: Optional[StrictStr] = "X-CSRF-Token"
    authjwt_refresh_csrf_header_name: Optional[StrictStr] = "X-CSRF-Token"
    authjwt_csrf_methods: Optional[Union[Set[CsrfMethod], List[CsrfMethod]]] = {
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    }

    @field_validator("authjwt_access_token_expires")
    @classmethod
    def validate_access_token_expires(cls, v):
        if v is True:
            raise ValueError(
                "The 'authjwt_access_token_expires' only accept value False (bool)"
            )
        return v

    @field_validator("authjwt_refresh_token_expires")
    @classmethod
    def validate_refresh_token_expires(cls, v):
        if v is True:
            raise ValueError(
                "The 'authjwt_refresh_token_expires' only accept value False (bool)"
            )
        return v

    @field_validator("authjwt_cookie_samesite")
    @classmethod
    def validate_cookie_samesite(cls, v):
        if v not in ["strict", "lax", "none"]:
            raise ValueError(
                "The 'authjwt_cookie_samesite' must be between 'strict', 'lax', 'none'"
            )
        return v

    model_config = ConfigDict(str_min_length=1, str_strip_whitespace=True)
