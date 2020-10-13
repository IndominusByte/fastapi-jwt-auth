import jwt
from re import match
from uuid import uuid4
from pydantic import ValidationError
from fastapi import Header, HTTPException
from fastapi_jwt_auth.config import LoadSettings
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Union, Callable, List

class AuthJWT:
    _access_token_expires = timedelta(minutes=15)
    _refresh_token_expires = timedelta(days=30)
    _decode_leeway = 0
    _blacklist_enabled = None
    _blacklist_token_checks = []
    _secret_key = None
    _algorithm = "HS256"
    _token_in_blacklist_callback = None
    _token = None

    def __init__(self,authorization: Optional[str] = Header(None)):
        """
        Get header Authorization with format 'Bearer <JWT>' and verified token, when Authorization header exists

        :param Authorization: get Authorization from the header when class initialize
        """
        if authorization:
            if match(r"Bearer\s",authorization) and len(authorization.split(' ')) == 2 and authorization.split(' ')[1]:
                self._token = authorization.split(' ')[1]
                # verified token and check if token is revoked
                raw_token = self._verified_token(encoded_token=self._token)
                if raw_token['user']['type'] in self._blacklist_token_checks:
                    self._check_token_is_revoked(raw_token)
            else:
                raise HTTPException(status_code=422,detail="Bad Authorization header. Expected value 'Bearer <JWT>'")

    def _get_jwt_identifier(self) -> str:
        return str(uuid4())

    def _get_int_from_datetime(self,value: datetime) -> int:
        """
        :param value: datetime with or without timezone, if don't contains timezone
                      it will managed as it is UTC
        :return: Seconds since the Epoch
        """
        if not isinstance(value, datetime):  # pragma: no cover
            raise TypeError('a datetime is required')
        return int(value.timestamp())

    def _create_token(
        self,
        identity: Union[str,int],
        type_token: str,
        exp_time: Optional[int],
        fresh: Optional[bool] = False,
        headers: Optional[Dict] = None
    ) -> bytes:
        """
        This function create token for access_token and refresh_token, when type_token
        is access add a fresh key to dictionary payload

        :param identity: Identifier for who this token is for example id or username from database.
        :param type_token: for indicate token is access_token or refresh_token
        :param exp_time: Set the duration of the JWT
        :param fresh: Optional when token is access_token this param required
        :param headers: valid dict for specifying additional headers in JWT header section

        :return: Encoded token
        """
        if type_token not in ['access','refresh']:
            raise TypeError("Type token must be between access or refresh")

        # raise an error if secret key doesn't exist
        if not self._secret_key:
            raise RuntimeError(
                "AUTHJWT_SECRET_KEY must be set when using symmetric algorithm {}".format(self._algorithm)
            )

        reserved_claims = {
            "iat": self._get_int_from_datetime(datetime.now(timezone.utc)),
            "nbf": self._get_int_from_datetime(datetime.now(timezone.utc)),
            "jti": self._get_jwt_identifier(),
        }

        custom_claims = {
            "identity": identity,
            "type": type_token
        }

        # for access_token only fresh needed
        if type_token == 'access':
            custom_claims['fresh'] = fresh

        if exp_time:
            reserved_claims['exp'] = exp_time

        return jwt.encode(
            {**reserved_claims, **{"user": custom_claims}},
            self._secret_key,
            algorithm=self._algorithm,
            headers=headers
        )

    def _verified_token(self,encoded_token: bytes) -> Dict[str,Union[str,int,bool]]:
        """
        Verified token and catch all error from jwt package and return decode token

        :param encoded_token: token hash
        :return: raw data from the hash token in the form of a dictionary
        """
        # raise an error if secret key doesn't exist
        if not self._secret_key:
            raise RuntimeError(
                "AUTHJWT_SECRET_KEY must be set when using symmetric algorithm {}".format(self._algorithm)
            )

        try:
            return jwt.decode(
                encoded_token,
                self._secret_key,
                leeway=self._decode_leeway,
                algorithms=self._algorithm
            )
        except Exception as err:
            raise HTTPException(status_code=422,detail=str(err))

    @classmethod
    def load_config(cls, settings: Callable[...,List[tuple]]) -> "AuthJWT":
        try:
            config = LoadSettings(**{key.lower():value for key,value in settings()})

            cls._access_token_expires = config.authjwt_access_token_expires
            cls._refresh_token_expires = config.authjwt_refresh_token_expires
            cls._decode_leeway = config.authjwt_decode_leeway
            cls._blacklist_enabled = config.authjwt_blacklist_enabled
            cls._blacklist_token_checks = config.authjwt_blacklist_token_checks
            cls._secret_key = config.authjwt_secret_key
            cls._algorithm = config.authjwt_algorithm
        except ValidationError:
            raise
        except Exception:
            raise TypeError("Config must be pydantic 'BaseSettings' or list of tuple")

    @classmethod
    def token_in_blacklist_loader(cls, callback: Callable[...,bool]) -> "AuthJWT":
        """
        This decorator sets the callback function that will be called when
        a protected endpoint is accessed and will check if the JWT has been
        been revoked. By default, this callback is not used.

        *HINT*: The callback must be a function that takes *args and **kwargs argument,
        args for object AuthJWT and this is not used, kwargs['decrypted_token'] is decode
        JWT (python dictionary) and returns *`True`* if the token has been blacklisted,
        or *`False`* otherwise.
        """
        cls._token_in_blacklist_callback = callback

    def blacklist_is_enabled(self) -> bool:
        """
        Check if AUTHJWT_BLACKLIST_ENABLED in env, not None and value is true
        """
        return self._blacklist_enabled is not None and self._blacklist_enabled == 'true'

    def has_token_in_blacklist_callback(self) -> bool:
        """
        Return True if token blacklist callback set
        """
        return self._token_in_blacklist_callback is not None

    def _check_token_is_revoked(self, raw_token: Dict[str,Union[str,int,bool]]) -> None:
        """
        Ensure that AUTHJWT_BLACKLIST_ENABLED is true and callback regulated, and then
        call function blacklist callback with passing decode JWT, if true
        raise exception Token has been revoked
        """
        if not self.blacklist_is_enabled():
            return

        if not self.has_token_in_blacklist_callback():
            raise RuntimeError("A token_in_blacklist_callback must be provided via "
                "the '@AuthJWT.token_in_blacklist_loader' if "
                "AUTHJWT_BLACKLIST_ENABLED is 'true'")

        if self._token_in_blacklist_callback.__func__(raw_token):
            raise HTTPException(status_code=401,detail="Token has been revoked")

    def create_access_token(
        self,
        identity: Union[str,int],
        fresh: Optional[bool] = False,
        headers: Optional[Dict] = None,
        expires_time: Optional[Union[timedelta,int,bool]] = None
    ) -> bytes:
        """
        Create a access token with 15 minutes for expired time (default),
        info for param and return please check to function create token

        :return: hash token
        """
        if not isinstance(identity, (str,int)):
            raise TypeError("identity must be a string or integer")
        if not isinstance(fresh, (bool)):
            raise TypeError("fresh must be a boolean")
        if expires_time and not isinstance(expires_time, (timedelta,int,bool)):
            raise TypeError("expires_time must be between timedelta, int, bool")

        # Dynamic token expired
        # if expires_time is False exp claim not created
        if expires_time is not False:
            expires_time = expires_time or self._access_token_expires

            if isinstance(expires_time, bool):
                expires_time = self._access_token_expires
            if isinstance(expires_time, timedelta):
                expires_time = int(expires_time.total_seconds())

            expired = self._get_int_from_datetime(datetime.now(timezone.utc)) + expires_time
        else:
            expired = None

        return self._create_token(
            identity=identity,
            type_token="access",
            exp_time=expired,
            fresh=fresh,
            headers=headers
        )

    def create_refresh_token(
        self,
        identity: Union[str,int],
        headers: Optional[Dict] = None,
        expires_time: Optional[Union[timedelta,int,bool]] = None
    ) -> bytes:
        """
        Create a refresh token with 30 days for expired time (default),
        info for param and return please check to function create token

        :return: hash token
        """
        if not isinstance(identity, (str,int)):
            raise TypeError("identity must be a string or integer")
        if expires_time and not isinstance(expires_time, (timedelta,int,bool)):
            raise TypeError("expires_time must be between timedelta, int, bool")

        # Dynamic token expired
        # if expires_time is False exp claim not created
        if expires_time is not False:
            expires_time = expires_time or self._refresh_token_expires

            if isinstance(expires_time, bool):
                expires_time = self._refresh_token_expires
            if isinstance(expires_time, timedelta):
                expires_time = int(expires_time.total_seconds())

            expired = self._get_int_from_datetime(datetime.now(timezone.utc)) + expires_time
        else:
            expired = None

        return self._create_token(
            identity=identity,
            type_token="refresh",
            exp_time=expired,
            headers=headers
        )

    def jwt_required(self) -> None:
        """
        Only access token can access this function

        :return: None
        """
        if not self._token:
            raise HTTPException(status_code=401,detail="Missing Authorization Header")

        if self.get_raw_jwt()['user']['type'] != 'access':
            raise HTTPException(status_code=422,detail="Only access tokens are allowed")

    def jwt_optional(self) -> None:
        """
        If an access token in present in the request you can get data from get_raw_jwt() or get_jwt_identity(),
        If no access token is present in the request, this endpoint will still be called, but
        get_raw_jwt() or get_jwt_identity() will return None

        :return: None
        """
        if self._token and self.get_raw_jwt()['user']['type'] != 'access':
            raise HTTPException(status_code=422,detail="Only access tokens are allowed")

    def jwt_refresh_token_required(self) -> None:
        """
        This function will ensure that the requester has a valid refresh token

        :return: None
        """
        if not self._token:
            raise HTTPException(status_code=401,detail="Missing Authorization Header")

        if self.get_raw_jwt()['user']['type'] != 'refresh':
            raise HTTPException(status_code=422,detail="Only refresh tokens are allowed")

    def fresh_jwt_required(self) -> None:
        """
        This function will ensure that the requester has a valid and fresh access token

        :return: None
        """
        if not self._token:
            raise HTTPException(status_code=401,detail="Missing Authorization Header")

        if self.get_raw_jwt()['user']['type'] != 'access':
            raise HTTPException(status_code=422,detail="Only access tokens are allowed")

        if not self.get_raw_jwt()['user']['fresh']:
            raise HTTPException(status_code=401,detail="Fresh token required")

    def get_raw_jwt(self) -> Optional[Dict[str,Union[str,int,bool]]]:
        """
        this will return the python dictionary which has all of the claims of the JWT that is accessing the endpoint.
        If no JWT is currently present, return None instead

        :return: claims of JWT
        """
        if self._token:
            return self._verified_token(encoded_token=self._token)
        return None

    def get_jti(self,encoded_token: bytes) -> str:
        """
        Returns the JTI (unique identifier) of an encoded JWT

        :return: string of JTI
        """
        return self._verified_token(encoded_token=encoded_token)['jti']

    def get_jwt_identity(self) -> Optional[Union[str,int]]:
        """
        this will return the identity of the JWT that is accessing this endpoint.
        If no JWT is present, `None` is returned instead.

        :return: identity of JWT
        """
        if self._token:
            return self._verified_token(encoded_token=self._token)['user']['identity']
        return None

    def get_unverified_jwt_headers(self,encoded_token: Optional[bytes] = None) -> dict:
        """
        Returns the Headers of an encoded JWT without verifying the actual signature of JWT

        :param encoded_token: The encoded JWT to get the Header from
        :return: JWT header parameters as a dictionary
        """
        encoded_token = encoded_token or self._token

        return jwt.get_unverified_header(encoded_token)
