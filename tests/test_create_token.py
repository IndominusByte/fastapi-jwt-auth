import pytest
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseSettings

def test_create_access_token(Authorize):
    class Settings(BaseSettings):
        AUTHJWT_SECRET_KEY: str = "testing"

    @AuthJWT.load_env
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
