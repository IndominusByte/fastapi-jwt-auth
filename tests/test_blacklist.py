import pytest
from fastapi_jwt_auth import AuthJWT
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient

# setting for blacklist token
blacklist = set()
AuthJWT._blacklist_enabled = 'true'
AuthJWT._secret_key = 'secret-key'

@AuthJWT.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist

@pytest.fixture(scope='function')
def client(monkeypatch):
    app = FastAPI()

    @app.get('/jwt-required')
    def jwt_required(Authorize: AuthJWT = Depends()):
        Authorize.jwt_required()
        return {'hello':'world'}

    @app.get('/jwt-optional')
    def jwt_optional(Authorize: AuthJWT = Depends()):
        Authorize.jwt_optional()
        return {'hello':'world'}

    @app.get('/jwt-refresh-required')
    def jwt_refresh_required(Authorize: AuthJWT = Depends()):
        Authorize.jwt_refresh_token_required()
        return {'hello':'world'}

    @app.get('/fresh-jwt-required')
    def fresh_jwt_required(Authorize: AuthJWT = Depends()):
        Authorize.fresh_jwt_required()
        return {'hello':'world'}

    client = TestClient(app)
    return client

@pytest.fixture(scope='module')
def access_token(Authorize):
    return Authorize.create_access_token(identity='test',fresh=True)

@pytest.fixture(scope='module')
def refresh_token(Authorize):
    return Authorize.create_refresh_token(identity='test')

@pytest.mark.parametrize("url",["/jwt-required","/jwt-optional","/fresh-jwt-required"])
def test_non_blacklisted_access_token(client,url,access_token,Authorize):
    response = client.get(url,headers={"Authorization":f"Bearer {access_token.decode('utf-8')}"})
    assert response.status_code == 200
    assert response.json() == {'hello':'world'}

    # revoke token in last test url
    if url == "/fresh-jwt-required":
        jti = Authorize.get_jti(access_token)
        blacklist.add(jti)

def test_non_blacklisted_refresh_token(client,refresh_token,Authorize):
    url = '/jwt-refresh-required'
    response = client.get(url,headers={"Authorization":f"Bearer {refresh_token.decode('utf-8')}"})
    assert response.status_code == 200
    assert response.json() == {'hello':'world'}

    # revoke token
    jti = Authorize.get_jti(refresh_token)
    blacklist.add(jti)

@pytest.mark.parametrize("url",["/jwt-required","/jwt-optional","/fresh-jwt-required"])
def test_blacklisted_access_token(client,url,access_token):
    response = client.get(url,headers={"Authorization":f"Bearer {access_token.decode('utf-8')}"})
    assert response.status_code == 401
    assert response.json() == {'detail': 'Token has been revoked'}

def test_blacklisted_refresh_token(client,refresh_token):
    url = '/jwt-refresh-required'
    response = client.get(url,headers={"Authorization":f"Bearer {refresh_token.decode('utf-8')}"})
    assert response.status_code == 401
    assert response.json() == {'detail': 'Token has been revoked'}
