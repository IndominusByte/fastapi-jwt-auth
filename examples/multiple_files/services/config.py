from os.path import abspath, dirname, join
from fastapi_jwt_auth import AuthJWT
from datetime import timedelta
from pydantic import BaseSettings
from typing import Literal
from redis import Redis

ENV_FILE = join(dirname(abspath(__file__)),".env")

class Settings(BaseSettings):
    db_url: str
    redis_db_host: str
    authjwt_access_token_expires: timedelta = timedelta(minutes=15)
    authjwt_refresh_token_expires: timedelta = timedelta(days=30)
    # remember literal type only available for python 3.8
    authjwt_blacklist_enabled: Literal['true','false']
    authjwt_secret_key: str

    class Config:
        env_file = ENV_FILE
        env_file_encoding = "utf-8"


settings = Settings()

conn_redis = Redis(host=settings.redis_db_host, port=6379, db=0,decode_responses=True)

# You can load env from pydantic or environment variable
@AuthJWT.load_env
def get_setting():
    return settings

@AuthJWT.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    entry = conn_redis.get(jti)
    return entry and entry == 'true'


ACCESS_EXPIRES = int(settings.authjwt_access_token_expires.total_seconds())
REFRESH_EXPIRES = int(settings.authjwt_refresh_token_expires.total_seconds())
