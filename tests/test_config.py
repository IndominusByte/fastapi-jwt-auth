import pytest
from .utils import reset_config
from fastapi_jwt_auth import AuthJWT
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from pydantic import BaseSettings
from datetime import timedelta

@pytest.fixture(scope='function')
def client():
    app = FastAPI()

    @app.get('/protected')
    def protected(Authorize: AuthJWT = Depends()):
        Authorize.jwt_required()

    client = TestClient(app)
    return client

def test_default_config():
    reset_config()

    assert AuthJWT._access_token_expires.__class__ == timedelta
    assert int(AuthJWT._access_token_expires.total_seconds()) == 900

    assert AuthJWT._refresh_token_expires.__class__ == timedelta
    assert int(AuthJWT._refresh_token_expires.total_seconds()) == 2592000

    assert AuthJWT._blacklist_enabled is None
    assert AuthJWT._secret_key is None
    assert AuthJWT._algorithm == 'HS256'
    assert AuthJWT._token_in_blacklist_callback is None
    assert AuthJWT._token is None

def test_token_with_other_value():
    class Settings(BaseSettings):
        authjwt_access_token_expires: timedelta = timedelta(minutes=1)
        authjwt_refresh_token_expires: timedelta = timedelta(days=1)

    @AuthJWT.load_env
    def get_settings():
        return Settings()

    assert timedelta(minutes=1) == AuthJWT._access_token_expires
    assert timedelta(days=1) == AuthJWT._refresh_token_expires

def test_token_config_not_int_or_timedelta():
    class SettingsOne(BaseSettings):
        authjwt_access_token_expires: str = "test"

    with pytest.raises(TypeError,match=r"AUTHJWT_ACCESS_TOKEN_EXPIRES"):
        @AuthJWT.load_env
        def get_settings_one():
            return SettingsOne()

    class SettingsTwo(BaseSettings):
        authjwt_refresh_token_expires: str = "test"

    with pytest.raises(TypeError,match=r"AUTHJWT_REFRESH_TOKEN_EXPIRES"):
        @AuthJWT.load_env
        def get_settings_two():
            return SettingsTwo()

def test_state_class_with_other_value_except_token():
    class Settings(BaseSettings):
        authjwt_blacklist_enabled: str = "true"
        authjwt_secret_key: str = "test"
        authjwt_algorithm: str = "test"

    @AuthJWT.load_env
    def get_settings():
        return Settings()

    assert AuthJWT._blacklist_enabled == 'true'
    assert AuthJWT._secret_key == 'test'
    assert AuthJWT._algorithm == 'test'

def test_secret_key_not_exist(client,Authorize):
    reset_config()

    with pytest.raises(RuntimeError,match=r"AUTHJWT_SECRET_KEY"):
        Authorize.create_access_token(identity='test')

    with pytest.raises(RuntimeError,match=r"AUTHJWT_SECRET_KEY"):
        client.get('/protected',headers={"Authorization":"Bearer test"})

def test_blacklist_enabled_without_callback(client,Authorize):
    # set authjwt_secret_key for create token
    class SettingsOne(BaseSettings):
        authjwt_secret_key: str = "secret-key"
        # AuthJWT blacklist won't trigger if value
        # env variable AUTHJWT_BLACKLIST_ENABLED not true
        authjwt_blacklist_enabled: str = "false"

    @AuthJWT.load_env
    def get_settings_one():
        return SettingsOne()

    token = Authorize.create_access_token(identity='test')
    response = client.get('/protected',headers={"Authorization": f"Bearer {token.decode('utf-8')}"})
    assert response.status_code == 200

    class SettingsTwo(BaseSettings):
        authjwt_blacklist_enabled: str = "true"

    @AuthJWT.load_env
    def get_settings_two():
        return SettingsTwo()

    with pytest.raises(RuntimeError,match=r"@AuthJWT.token_in_blacklist_loader"):
        response = client.get('/protected',headers={"Authorization": f"Bearer {token.decode('utf-8')}"})

def test_load_env_from_outside():
    # correct data
    @AuthJWT.load_env
    def get_valid_settings():
        return [
            ("authjwt_access_token_expires",timedelta(minutes=2)),
            ("authjwt_refresh_token_expires",timedelta(days=5)),
            ("authjwt_blacklist_enabled","false"),
            ("authjwt_secret_key","testing"),
            ("authjwt_algorithm","HS256")
        ]

    assert AuthJWT._access_token_expires == timedelta(minutes=2)
    assert AuthJWT._refresh_token_expires == timedelta(days=5)
    assert AuthJWT._blacklist_enabled == "false"
    assert AuthJWT._secret_key == "testing"
    assert AuthJWT._algorithm == "HS256"

    with pytest.raises(ValueError):
        @AuthJWT.load_env
        def invalid_data():
            return "test"

    with pytest.raises(TypeError,match=r"AUTHJWT_ACCESS_TOKEN_EXPIRES"):
        @AuthJWT.load_env
        def get_invalid_access_token():
            return [("authjwt_access_token_expires","lol")]

    with pytest.raises(TypeError,match=r"AUTHJWT_REFRESH_TOKEN_EXPIRES"):
        @AuthJWT.load_env
        def get_invalid_refresh_token():
            return [("authjwt_refresh_token_expires","lol")]

    with pytest.raises(TypeError,match=r"AUTHJWT_BLACKLIST_ENABLED"):
        @AuthJWT.load_env
        def get_invalid_blacklist():
            return [("authjwt_blacklist_enabled","test")]

    with pytest.raises(TypeError,match=r"AUTHJWT_SECRET_KEY"):
        @AuthJWT.load_env
        def get_invalid_secret_key():
            return [("authjwt_secret_key",123)]

    with pytest.raises(TypeError,match=r"AUTHJWT_ALGORITHM"):
        @AuthJWT.load_env
        def get_invalid_algorithm():
            return [("authjwt_algorithm",123)]

    reset_config()
