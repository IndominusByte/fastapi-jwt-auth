import pytest, jwt
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseSettings
from datetime import timedelta, datetime, timezone

def test_create_access_token(Authorize):
    class Settings(BaseSettings):
        AUTHJWT_SECRET_KEY: str = "testing"
        AUTHJWT_ACCESS_TOKEN_EXPIRES: int = 2
        AUTHJWT_REFRESH_TOKEN_EXPIRES: int = 4

    @AuthJWT.load_config
    def get_settings():
        return Settings()

    with pytest.raises(TypeError,match=r"missing 1 required positional argument"):
        Authorize.create_access_token()

    with pytest.raises(TypeError,match=r"subject"):
        Authorize.create_access_token(subject=0.123)

    with pytest.raises(TypeError,match=r"fresh"):
        Authorize.create_access_token(subject="test",fresh="lol")

    with pytest.raises(ValueError,match=r"dictionary update sequence element"):
        Authorize.create_access_token(subject=1,headers="test")

def test_create_refresh_token(Authorize):
    with pytest.raises(TypeError,match=r"missing 1 required positional argument"):
        Authorize.create_refresh_token()

    with pytest.raises(TypeError,match=r"subject"):
        Authorize.create_refresh_token(subject=0.123)

    with pytest.raises(ValueError,match=r"dictionary update sequence element"):
        Authorize.create_refresh_token(subject=1,headers="test")

def test_create_dynamic_access_token_expires(Authorize):
    expires_time = int(datetime.now(timezone.utc).timestamp()) + 90
    token = Authorize.create_access_token(subject=1,expires_time=90)
    assert jwt.decode(token,"testing",algorithms="HS256")['exp'] == expires_time

    expires_time = int(datetime.now(timezone.utc).timestamp()) + 86400
    token = Authorize.create_access_token(subject=1,expires_time=timedelta(days=1))
    assert jwt.decode(token,"testing",algorithms="HS256")['exp'] == expires_time

    expires_time = int(datetime.now(timezone.utc).timestamp()) + 2
    token = Authorize.create_access_token(subject=1,expires_time=True)
    assert jwt.decode(token,"testing",algorithms="HS256")['exp'] == expires_time

    token = Authorize.create_access_token(subject=1,expires_time=False)
    assert 'exp' not in jwt.decode(token,"testing",algorithms="HS256")

    with pytest.raises(TypeError,match=r"expires_time"):
        Authorize.create_access_token(subject=1,expires_time="test")

def test_create_dynamic_refresh_token_expires(Authorize):
    expires_time = int(datetime.now(timezone.utc).timestamp()) + 90
    token = Authorize.create_refresh_token(subject=1,expires_time=90)
    assert jwt.decode(token,"testing",algorithms="HS256")['exp'] == expires_time

    expires_time = int(datetime.now(timezone.utc).timestamp()) + 86400
    token = Authorize.create_refresh_token(subject=1,expires_time=timedelta(days=1))
    assert jwt.decode(token,"testing",algorithms="HS256")['exp'] == expires_time

    expires_time = int(datetime.now(timezone.utc).timestamp()) + 4
    token = Authorize.create_refresh_token(subject=1,expires_time=True)
    assert jwt.decode(token,"testing",algorithms="HS256")['exp'] == expires_time

    token = Authorize.create_refresh_token(subject=1,expires_time=False)
    assert 'exp' not in jwt.decode(token,"testing",algorithms="HS256")

    with pytest.raises(TypeError,match=r"expires_time"):
        Authorize.create_refresh_token(subject=1,expires_time="test")

def test_create_token_invalid_type_data_audience(Authorize):
    with pytest.raises(TypeError,match=r"audience"):
        Authorize.create_access_token(subject=1,audience=1)

    with pytest.raises(TypeError,match=r"audience"):
        Authorize.create_refresh_token(subject=1,audience=1)

def test_create_token_invalid_algorithm(Authorize):
    with pytest.raises(ValueError,match=r"Algorithm"):
        Authorize.create_access_token(subject=1,algorithm="test")

    with pytest.raises(ValueError,match=r"Algorithm"):
        Authorize.create_refresh_token(subject=1,algorithm="test")

def test_create_token_invalid_type_data_algorithm(Authorize):
    with pytest.raises(TypeError,match=r"algorithm"):
        Authorize.create_access_token(subject=1,algorithm=1)

    with pytest.raises(TypeError,match=r"algorithm"):
        Authorize.create_refresh_token(subject=1,algorithm=1)

def test_create_token_invalid_user_claims(Authorize):
    with pytest.raises(TypeError,match=r"user_claims"):
        Authorize.create_access_token(subject=1,user_claims="asd")
    with pytest.raises(TypeError,match=r"user_claims"):
        Authorize.create_refresh_token(subject=1,user_claims="asd")

def test_create_valid_user_claims(Authorize):
    access_token = Authorize.create_access_token(subject=1,user_claims={"my_access":"yeah"})
    refresh_token = Authorize.create_refresh_token(subject=1,user_claims={"my_refresh":"hello"})

    assert jwt.decode(access_token,"testing",algorithms="HS256")['my_access'] == "yeah"
    assert jwt.decode(refresh_token,"testing",algorithms="HS256")['my_refresh'] == "hello"
