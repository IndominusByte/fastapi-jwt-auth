import pytest, jwt
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseSettings
from datetime import timedelta, datetime, timezone

def test_create_access_token(Authorize):
    class Settings(BaseSettings):
        AUTHJWT_SECRET_KEY: str = "testing"
        AUTHJWT_ACCESS_TOKEN_EXPIRES: int = 1
        AUTHJWT_REFRESH_TOKEN_EXPIRES: int = 2

    @AuthJWT.load_config
    def get_settings():
        return Settings()

    with pytest.raises(TypeError,match=r"missing 1 required positional argument"):
        Authorize.create_access_token()

    with pytest.raises(TypeError,match=r"identity"):
        Authorize.create_access_token(identity=0.123)

    with pytest.raises(TypeError,match=r"fresh"):
        Authorize.create_access_token(identity="test",fresh="lol")

    with pytest.raises(ValueError,match=r"dictionary update sequence element"):
        Authorize.create_access_token(identity=1,headers="test")

def test_create_refresh_token(Authorize):
    with pytest.raises(TypeError,match=r"missing 1 required positional argument"):
        Authorize.create_refresh_token()

    with pytest.raises(TypeError,match=r"identity"):
        Authorize.create_refresh_token(identity=0.123)

    with pytest.raises(ValueError,match=r"dictionary update sequence element"):
        Authorize.create_refresh_token(identity=1,headers="test")

def test_create_dynamic_access_token_expires(Authorize):
    expires_time = int(datetime.now(timezone.utc).timestamp()) + 90
    token = Authorize.create_access_token(identity=1,expires_time=90)
    assert jwt.decode(token,"testing",algorithms="HS256")['exp'] == expires_time

    expires_time = int(datetime.now(timezone.utc).timestamp()) + 86400
    token = Authorize.create_access_token(identity=1,expires_time=timedelta(days=1))
    assert jwt.decode(token,"testing",algorithms="HS256")['exp'] == expires_time

    expires_time = int(datetime.now(timezone.utc).timestamp()) + 1
    token = Authorize.create_access_token(identity=1,expires_time=True)
    assert jwt.decode(token,"testing",algorithms="HS256")['exp'] == expires_time

    token = Authorize.create_access_token(identity=1,expires_time=False)
    assert 'exp' not in jwt.decode(token,"testing",algorithms="HS256")

    with pytest.raises(TypeError,match=r"expires_time"):
        Authorize.create_access_token(identity=1,expires_time="test")

def test_create_dynamic_refresh_token_expires(Authorize):
    expires_time = int(datetime.now(timezone.utc).timestamp()) + 90
    token = Authorize.create_refresh_token(identity=1,expires_time=90)
    assert jwt.decode(token,"testing",algorithms="HS256")['exp'] == expires_time

    expires_time = int(datetime.now(timezone.utc).timestamp()) + 86400
    token = Authorize.create_refresh_token(identity=1,expires_time=timedelta(days=1))
    assert jwt.decode(token,"testing",algorithms="HS256")['exp'] == expires_time

    expires_time = int(datetime.now(timezone.utc).timestamp()) + 2
    token = Authorize.create_refresh_token(identity=1,expires_time=True)
    assert jwt.decode(token,"testing",algorithms="HS256")['exp'] == expires_time

    token = Authorize.create_refresh_token(identity=1,expires_time=False)
    assert 'exp' not in jwt.decode(token,"testing",algorithms="HS256")

    with pytest.raises(TypeError,match=r"expires_time"):
        Authorize.create_refresh_token(identity=1,expires_time="test")
