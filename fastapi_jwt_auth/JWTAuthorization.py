import jwt, uuid, re
from fastapi import Header, HTTPException
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Union
from redis import Redis, ConnectionError

class AuthJWT:
    _ACCESS_TOKEN_EXPIRES = 2
    _REFRESH_TOKEN_EXPIRES = 1
    _REDIS_DB_HOST = 'localhost'
    _REDIS_DB_PORT = 6379
    _SECRET_KEY = 'secretkey'
    _ALGORITHM = 'HS256'
    _TOKEN = None

    def __init__(self,Authorization: str = Header(None)):
        """
        Get header Authorization with format 'Bearer <JWT>' and verified token, when Authorization header exists

        :param Authorization: get Authorization from the header when class initialize
        """
        if Authorization:
            if re.match(r"Bearer\s",Authorization) and len(Authorization.split(' ')) == 2 and Authorization.split(' ')[1]:
                self._TOKEN = Authorization.split(' ')[1]
                # verified token and check if token is revoked
                raw_token = self._verified_token(encoded_token=self._TOKEN)
                # if connection redis is available check token revoke
                self._is_redis_available()
                self._check_token_is_revoked(raw_token['jti'])
            else:
                raise HTTPException(status_code=422,detail="Bad Authorization header. Expected value 'Bearer <JWT>'")

    @staticmethod
    def get_jwt_id() -> str:
        return str(uuid.uuid4())

    @staticmethod
    def get_int_from_datetime(value: datetime) -> int:
        """
        :param value: datetime with or without timezone, if don't contains timezone
                      it will managed as it is UTC
        :return: Seconds since the Epoch
        """
        if not isinstance(value, datetime):  # pragma: no cover
            raise TypeError('a datetime is required')
        return int(value.timestamp())

    @staticmethod
    def create_token(identity: int, type_token: str, exp_time: timedelta, fresh: Optional[bool] = False) -> bytes:
        """
        This function create token for access_token and refresh_token, when type_token
        is access add a fresh key to dictionary payload

        :param identity: Identifier for who this token is for example id or username from database.
        :param type_token: for indicate token is access_token or refresh_token
        :param fresh: Optional when token is access_token this param required

        :return: Encoded token
        """
        if type_token not in ['access','refresh']:
            raise ValueError("Type token must be between access or refresh")

        payload = {
            "iat": AuthJWT.get_int_from_datetime(datetime.now(timezone.utc)),
            "nbf": AuthJWT.get_int_from_datetime(datetime.now(timezone.utc)),
            "jti": AuthJWT.get_jwt_id(),
            "exp": AuthJWT.get_int_from_datetime(datetime.now(timezone.utc) + exp_time),
            "identity": identity,
            "type": type_token
        }

        # for access_token only fresh needed
        if type_token == 'access':
            payload['fresh'] = fresh

        return jwt.encode(payload,AuthJWT._SECRET_KEY,algorithm=AuthJWT._ALGORITHM)

    def _verified_token(self,encoded_token: bytes) -> Dict[str,Union[str,int,bool]]:
        """
        Verified token and catch all error from jwt package and return decode token

        :param encoded_token: token hash
        :return: raw data from the hash token in the form of a dictionary
        """
        try:
            return jwt.decode(encoded_token,self._SECRET_KEY,algorithms=self._ALGORITHM)
        except jwt.ExpiredSignatureError as err:
            raise HTTPException(status_code=422,detail=str(err))
        except jwt.DecodeError as err:
            raise HTTPException(status_code=422,detail=str(err))
        except jwt.InvalidAlgorithmError as err:
            raise HTTPException(status_code=422,detail=str(err))
        except jwt.InvalidKeyError as err:
            raise HTTPException(status_code=422,detail=str(err))
        except jwt.InvalidTokenError as err:
            raise HTTPException(status_code=422,detail=str(err))
        except jwt.InvalidIssuerError as err:
            raise HTTPException(status_code=422,detail=str(err))
        except jwt.InvalidAudienceError as err:
            raise HTTPException(status_code=422,detail=str(err))
        except jwt.InvalidIssuedAtError as err:
            raise HTTPException(status_code=422,detail=str(err))
        except jwt.InvalidSignatureError as err:
            raise HTTPException(status_code=422,detail=str(err))
        except jwt.ImmatureSignatureError as err:
            raise HTTPException(status_code=422,detail=str(err))
        except jwt.MissingRequiredClaimError as err:
            raise HTTPException(status_code=422,detail=str(err))

    def _conn_redis(self) -> Redis:
        """
        Return connection for redis
        """
        return Redis(host=self._REDIS_DB_HOST, port=self._REDIS_DB_PORT, db=0,decode_responses=True)

    def _is_redis_available(self) -> None:
        """
        Check connection redis is ready

        :return: None
        """
        try:
            redis = self._conn_redis()
            redis.ping()
        except ConnectionError as err:
            raise HTTPException(status_code=500,detail=f"REDIS CONNECTION -> {err}")

    def _check_token_is_revoked(self, jti: str) -> None:
        """
        If JTI exists in redis and value is true raise http exception

        :param jti: key for redis db
        :return: None
        """
        redis = self._conn_redis()
        entry = redis.get(jti)
        if entry and entry == 'true':
            raise HTTPException(status_code=401,detail="Token has been revoked")

    @classmethod
    def revoke_access_token(cls, jti: str) -> None:
        """
        Store JTI (unique identifier) to redis and set expired same as create an access token expired,
        with the value true

        :param jti: key for redis db
        :return: None
        """
        redis = cls._conn_redis(cls)
        expired_time = int(timedelta(minutes=cls._ACCESS_TOKEN_EXPIRES).total_seconds())
        redis.setex(jti,expired_time,'true')

    @classmethod
    def revoke_refresh_token(cls, jti: str) -> None:
        """
        Store JTI (unique identifier) to redis and set expired same as create an refresh token expired,
        with the value true

        :param jti: key for redis db
        :return: None
        """
        redis = cls._conn_redis(cls)
        expired_time = int(timedelta(days=cls._REFRESH_TOKEN_EXPIRES).total_seconds())
        redis.setex(jti,expired_time,'true')

    @staticmethod
    def create_access_token(identity: Union[str,int], fresh: Optional[bool] = False) -> bytes:
        """
        Create a token with minutes for expired time, info for param and return please check to
        function create token

        :return: hash token
        """
        return AuthJWT.create_token(
            identity=identity,
            type_token="access",
            fresh=fresh,
            exp_time=timedelta(minutes=AuthJWT._ACCESS_TOKEN_EXPIRES)
        )

    @staticmethod
    def create_refresh_token(identity: Union[str,int]) -> bytes:
        """
        Create a token with days for expired time, info for param and return please check to
        function create token

        :return: hash token
        """
        return AuthJWT.create_token(
            identity=identity,
            type_token="refresh",
            exp_time=timedelta(days=AuthJWT._REFRESH_TOKEN_EXPIRES)
        )

    def jwt_required(self) -> None:
        """
        Only access token can access this function

        :return: None
        """
        if not self._TOKEN:
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
        if self._TOKEN and self.get_raw_jwt()['type'] != 'access':
            raise HTTPException(status_code=422,detail="Only access tokens are allowed")

    def jwt_refresh_token_required(self) -> None:
        """
        This function will ensure that the requester has a valid refresh token

        :return: None
        """
        if not self._TOKEN:
            raise HTTPException(status_code=401,detail="Missing Authorization Header")

        if self.get_raw_jwt()['type'] != 'refresh':
            raise HTTPException(status_code=422,detail="Only refresh tokens are allowed")

    def fresh_jwt_required(self) -> None:
        """
        This function will ensure that the requester has a valid and fresh access token

        :return: None
        """
        if not self._TOKEN:
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
        if self._TOKEN:
            return self._verified_token(encoded_token=self._TOKEN)
        return None

    @classmethod
    def get_jti(cls,encoded_token: bytes) -> str:
        """
        Returns the JTI (unique identifier) of an encoded JWT

        :return: string of JTI
        """
        return cls._verified_token(cls,encoded_token=encoded_token)['jti']

    def get_jwt_identity(self) -> Optional[Union[str,int]]:
        """
        this will return the identity of the JWT that is accessing this endpoint.
        If no JWT is present, `None` is returned instead.

        :return: identity of JWT
        """
        if self._TOKEN:
            return self._verified_token(encoded_token=self._TOKEN)['identity']
        return None
