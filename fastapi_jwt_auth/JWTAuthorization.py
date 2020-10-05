import jwt, uuid, re, os
from fastapi import Header, HTTPException
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Union, Callable, List

class AuthJWT:
    _access_token_expires = os.getenv("AUTHJWT_ACCESS_TOKEN_EXPIRES") or timedelta(minutes=15)
    _refresh_token_expires = os.getenv("AUTHJWT_REFRESH_TOKEN_EXPIRES") or timedelta(days=30)
    _blacklist_enabled = os.getenv("AUTHJWT_BLACKLIST_ENABLED") or None
    _secret_key = os.getenv("AUTHJWT_SECRET_KEY") or None
    _algorithm = os.getenv("AUTHJWT_ALGORITHM") or "HS256"
    _token_in_blacklist_callback = None
    _token = None

    def __init__(self,authorization: Optional[str] = Header(None)):
        """
        Get header Authorization with format 'Bearer <JWT>' and verified token, when Authorization header exists

        :param Authorization: get Authorization from the header when class initialize
        """
        if authorization:
            if re.match(r"Bearer\s",authorization) and len(authorization.split(' ')) == 2 and authorization.split(' ')[1]:
                self._token = authorization.split(' ')[1]
                # verified token and check if token is revoked
                raw_token = self._verified_token(encoded_token=self._token)
                self._check_token_is_revoked(raw_token)
            else:
                raise HTTPException(status_code=422,detail="Bad Authorization header. Expected value 'Bearer <JWT>'")

    def _get_jwt_identifier(self) -> str:
        return str(uuid.uuid4())

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
        exp_time: int,
        fresh: Optional[bool] = False
    ) -> bytes:
        """
        This function create token for access_token and refresh_token, when type_token
        is access add a fresh key to dictionary payload

        :param identity: Identifier for who this token is for example id or username from database.
        :param type_token: for indicate token is access_token or refresh_token
        :param exp_time: Set the duration of the JWT
        :param fresh: Optional when token is access_token this param required

        :return: Encoded token
        """
        if type_token not in ['access','refresh']:
            raise TypeError("Type token must be between access or refresh")

        # raise an error if secret key doesn't exist
        if not self._secret_key:
            raise RuntimeError(
                "AUTHJWT_SECRET_KEY must be set when using symmetric algorithm {}".format(self._algorithm)
            )

        # passing instance itself because we call create_access_token
        # and create_refresh_token with classmethod
        payload = {
            "iat": self._get_int_from_datetime(datetime.now(timezone.utc)),
            "nbf": self._get_int_from_datetime(datetime.now(timezone.utc)),
            "jti": self._get_jwt_identifier(),
            "exp": exp_time,
            "identity": identity,
            "type": type_token
        }

        # for access_token only fresh needed
        if type_token == 'access':
            payload['fresh'] = fresh

        return jwt.encode(
            payload,
            self._secret_key,
            algorithm=self._algorithm
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
                algorithms=self._algorithm
            )
        except jwt.exceptions.ExpiredSignatureError as err:
            raise HTTPException(status_code=422,detail=str(err))
        except jwt.exceptions.DecodeError as err:
            raise HTTPException(status_code=422,detail=str(err))
        except jwt.exceptions.InvalidAlgorithmError as err:
            raise HTTPException(status_code=422,detail=str(err))
        except jwt.exceptions.InvalidKeyError as err:
            raise HTTPException(status_code=422,detail=str(err))
        except jwt.exceptions.InvalidTokenError as err:
            raise HTTPException(status_code=422,detail=str(err))
        except jwt.exceptions.InvalidIssuerError as err:
            raise HTTPException(status_code=422,detail=str(err))
        except jwt.exceptions.InvalidAudienceError as err:
            raise HTTPException(status_code=422,detail=str(err))
        except jwt.exceptions.InvalidIssuedAtError as err:
            raise HTTPException(status_code=422,detail=str(err))
        except jwt.exceptions.InvalidSignatureError as err:
            raise HTTPException(status_code=422,detail=str(err))
        except jwt.exceptions.ImmatureSignatureError as err:
            raise HTTPException(status_code=422,detail=str(err))
        except jwt.exceptions.MissingRequiredClaimError as err:
            raise HTTPException(status_code=422,detail=str(err))

    @classmethod
    def load_env(cls, settings: Callable[...,List[tuple]]) -> "AuthJWT":
        try:
            for key, value in settings():
                if key.lower() == "authjwt_access_token_expires":
                    if not isinstance(value, (timedelta, int)):
                        raise TypeError("The 'AUTHJWT_ACCESS_TOKEN_EXPIRES' must be a timedelta or integer")
                    cls._access_token_expires = value

                if key.lower() == "authjwt_refresh_token_expires":
                    if not isinstance(value, (timedelta, int)):
                        raise TypeError("The 'AUTHJWT_REFRESH_TOKEN_EXPIRES' must be a timedelta or integer")
                    cls._refresh_token_expires = value

                if key.lower() == "authjwt_blacklist_enabled":
                    if value not in ['true','false']:
                        raise TypeError("The 'AUTHJWT_BLACKLIST_ENABLED' must be between 'true' or 'false'")
                    cls._blacklist_enabled = value

                if key.lower() == "authjwt_secret_key":
                    if not isinstance(value, str):
                        raise TypeError("The 'AUTHJWT_SECRET_KEY' must be an string")
                    cls._secret_key = value

                if key.lower() == "authjwt_algorithm":
                    if not isinstance(value, str):
                        raise TypeError("The 'AUTHJWT_ALGORITHM' must be an string")
                    cls._algorithm = value
        except TypeError:
            raise

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

    def create_access_token(self,identity: Union[str,int], fresh: Optional[bool] = False) -> bytes:
        """
        Create a token with minutes for expired time (default), info for param and return please check to
        function create token

        :return: hash token
        """
        if not isinstance(identity, (str,int)):
            raise TypeError("identity must be a string or integer")
        if not isinstance(fresh, (bool)):
            raise TypeError("fresh must be a boolean")

        if isinstance(self._access_token_expires,timedelta):
            expired = self._get_int_from_datetime(datetime.now(timezone.utc) + self._access_token_expires)
        else:
            try:
                expired = self._get_int_from_datetime(datetime.now(timezone.utc)) + int(self._access_token_expires)
            except Exception:
                raise TypeError("The 'AUTHJWT_ACCESS_TOKEN_EXPIRES' must be a timedelta or integer")

        return self._create_token(
            identity=identity,
            type_token="access",
            fresh=fresh,
            exp_time=expired
        )

    def create_refresh_token(self,identity: Union[str,int]) -> bytes:
        """
        Create a token with days for expired time (default), info for param and return please check to
        function create token

        :return: hash token
        """
        if not isinstance(identity, (str,int)):
            raise TypeError("identity must be a string or integer")

        if isinstance(self._refresh_token_expires,timedelta):
            expired = self._get_int_from_datetime(datetime.now(timezone.utc) + self._refresh_token_expires)
        else:
            try:
                expired = self._get_int_from_datetime(datetime.now(timezone.utc)) + int(self._refresh_token_expires)
            except Exception:
                raise TypeError("The 'AUTHJWT_REFRESH_TOKEN_EXPIRES' must be a timedelta or integer")

        return self._create_token(
            identity=identity,
            type_token="refresh",
            exp_time=expired
        )

    def jwt_required(self) -> None:
        """
        Only access token can access this function

        :return: None
        """
        if not self._token:
            raise HTTPException(status_code=401,detail="Missing Authorization Header")

        if self.get_raw_jwt()['type'] != 'access':
            raise HTTPException(status_code=422,detail="Only access tokens are allowed")

    def jwt_optional(self) -> None:
        """
        If an access token in present in the request you can get data from get_raw_jwt() or get_jwt_identity(),
        If no access token is present in the request, this endpoint will still be called, but
        get_raw_jwt() or get_jwt_identity() will return None

        :return: None
        """
        if self._token and self.get_raw_jwt()['type'] != 'access':
            raise HTTPException(status_code=422,detail="Only access tokens are allowed")

    def jwt_refresh_token_required(self) -> None:
        """
        This function will ensure that the requester has a valid refresh token

        :return: None
        """
        if not self._token:
            raise HTTPException(status_code=401,detail="Missing Authorization Header")

        if self.get_raw_jwt()['type'] != 'refresh':
            raise HTTPException(status_code=422,detail="Only refresh tokens are allowed")

    def fresh_jwt_required(self) -> None:
        """
        This function will ensure that the requester has a valid and fresh access token

        :return: None
        """
        if not self._token:
            raise HTTPException(status_code=401,detail="Missing Authorization Header")

        if self.get_raw_jwt()['type'] != 'access':
            raise HTTPException(status_code=422,detail="Only access tokens are allowed")

        if not self.get_raw_jwt()['fresh']:
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
            return self._verified_token(encoded_token=self._token)['identity']
        return None
