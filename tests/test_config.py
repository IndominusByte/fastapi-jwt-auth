import pytest
from .utils import reset_config
from fastapi_jwt_auth import AuthJWT
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
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

def test_token_with_other_value(monkeypatch):
    monkeypatch.setenv("AUTHJWT_ACCESS_TOKEN_EXPIRES","60")
    monkeypatch.setenv("AUTHJWT_REFRESH_TOKEN_EXPIRES","86400")
    reset_config()
    assert int(timedelta(minutes=1).total_seconds()) == int(AuthJWT._access_token_expires)
    assert int(timedelta(days=1).total_seconds()) == int(AuthJWT._refresh_token_expires)

def test_token_config_not_int(monkeypatch):
    monkeypatch.setenv("AUTHJWT_ACCESS_TOKEN_EXPIRES","test")
    monkeypatch.setenv("AUTHJWT_REFRESH_TOKEN_EXPIRES","test")
    reset_config()
    with pytest.raises(ValueError,match=r"AUTHJWT_ACCESS_TOKEN_EXPIRES"):
        AuthJWT.create_access_token(identity='test')

    with pytest.raises(ValueError,match=r"AUTHJWT_REFRESH_TOKEN_EXPIRES"):
        AuthJWT.create_refresh_token(identity='test')

def test_state_class_with_other_value_except_token(monkeypatch):
    monkeypatch.setenv("AUTHJWT_BLACKLIST_ENABLED","test")
    monkeypatch.setenv("AUTHJWT_SECRET_KEY","test")
    monkeypatch.setenv("AUTHJWT_ALGORITHM","test")
    reset_config()
    assert AuthJWT._blacklist_enabled == 'test'
    assert AuthJWT._secret_key == 'test'
    assert AuthJWT._algorithm == 'test'

def test_secret_key_not_exist(client):
    reset_config()
    with pytest.raises(RuntimeError,match=r"AUTHJWT_SECRET_KEY"):
        AuthJWT.create_access_token(identity='test')

    with pytest.raises(RuntimeError,match=r"AUTHJWT_SECRET_KEY"):
        client.get('/protected',headers={"Authorization":"Bearer test"})

def test_blacklist_enabled_without_callback(monkeypatch,client):
    # set authjwt_secret_key for create token
    monkeypatch.setenv("AUTHJWT_SECRET_KEY","secret-key")
    reset_config()
    token = AuthJWT.create_access_token(identity='test')
    response = client.get('/protected',headers={"Authorization": f"Bearer {token.decode('utf-8')}"})
    assert response.status_code == 200
    # AuthJWT blacklist won't trigger if value
    # env variable AUTHJWT_BLACKLIST_ENABLED not true
    monkeypatch.setenv("AUTHJWT_BLACKLIST_ENABLED","false")
    reset_config()
    response = client.get('/protected',headers={"Authorization": f"Bearer {token.decode('utf-8')}"})
    assert response.status_code == 200
    monkeypatch.setenv("AUTHJWT_BLACKLIST_ENABLED","true")
    reset_config()
    with pytest.raises(RuntimeError,match=r"@AuthJWT.token_in_blacklist_loader"):
        response = client.get('/protected',headers={"Authorization": f"Bearer {token.decode('utf-8')}"})
