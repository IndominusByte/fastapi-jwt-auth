import pytest
from fastapi_jwt_auth import AuthJWT
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient

@pytest.fixture(scope='function')
def client():
    app = FastAPI()

    @app.get('/jwt-required')
    def jwt_required(Authorize: AuthJWT = Depends()):
        Authorize.jwt_required()
        return {'hello':'world'}

    @app.get('/jwt-optional')
    def jwt_optional(Authorize: AuthJWT = Depends()):
        Authorize.jwt_optional()
        if Authorize.get_jwt_identity():
            return {'hello':'world'}
        return {'hello':'anonym'}

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

@pytest.mark.parametrize("url",["/jwt-required","/jwt-refresh-required","/fresh-jwt-required"])
def test_missing_header(client,url):
    response = client.get(url)
    assert response.status_code == 401
    assert response.json() == {'detail': 'Missing Authorization Header'}

@pytest.mark.parametrize("url",["/jwt-required","/jwt-optional","/fresh-jwt-required"])
def test_only_access_token_allowed(client,url,Authorize):
    token = Authorize.create_refresh_token(identity='test')
    response = client.get(url,headers={"Authorization":f"Bearer {token.decode('utf-8')}"})
    assert response.status_code == 422
    assert response.json() == {'detail': 'Only access tokens are allowed'}

def test_jwt_required(client,Authorize):
    url = '/jwt-required'
    token = Authorize.create_access_token(identity='test')
    response = client.get(url,headers={"Authorization":f"Bearer {token.decode('utf-8')}"})
    assert response.status_code == 200
    assert response.json() == {'hello':'world'}

def test_jwt_optional(client,Authorize):
    url = '/jwt-optional'
    # if header not define return anonym user
    response = client.get(url)
    assert response.status_code == 200
    assert response.json() == {'hello': 'anonym'}

    token = Authorize.create_access_token(identity='test')
    response = client.get(url,headers={"Authorization":f"Bearer {token.decode('utf-8')}"})
    assert response.status_code == 200
    assert response.json() == {'hello': 'world'}

def test_refresh_required(client,Authorize):
    url = '/jwt-refresh-required'
    # only refresh token allowed
    token = Authorize.create_access_token(identity='test')
    response = client.get(url,headers={"Authorization":f"Bearer {token.decode('utf-8')}"})
    assert response.status_code == 422
    assert response.json() == {'detail': 'Only refresh tokens are allowed'}

    token = Authorize.create_refresh_token(identity='test')
    response = client.get(url,headers={"Authorization":f"Bearer {token.decode('utf-8')}"})
    assert response.status_code == 200
    assert response.json() == {'hello':'world'}

def test_fresh_jwt_required(client,Authorize):
    url = '/fresh-jwt-required'
    # only fresh token allowed
    token = Authorize.create_access_token(identity='test')
    response = client.get(url,headers={"Authorization":f"Bearer {token.decode('utf-8')}"})
    assert response.status_code == 401
    assert response.json() == {'detail': 'Fresh token required'}

    token = Authorize.create_access_token(identity='test',fresh=True)
    response = client.get(url,headers={"Authorization":f"Bearer {token.decode('utf-8')}"})
    assert response.status_code == 200
    assert response.json() == {'hello':'world'}
