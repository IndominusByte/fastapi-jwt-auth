import pytest
from fastapi_jwt_auth import AuthJWT
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient

@pytest.fixture(scope='function')
def client():
    app = FastAPI()

    @app.get('/protected')
    def protected(Authorize: AuthJWT = Depends()):
        Authorize.jwt_required()
        return {'hello':'world'}

    @app.get('/get_headers_access')
    def get_headers_access(Authorize: AuthJWT = Depends()):
        Authorize.jwt_required()
        return Authorize.get_unverified_jwt_headers()

    @app.get('/get_headers_refresh')
    def get_headers_refresh(Authorize: AuthJWT = Depends()):
        Authorize.jwt_refresh_token_required()
        return Authorize.get_unverified_jwt_headers()

    client = TestClient(app)
    return client

def test_header_without_jwt(client):
    response = client.get('/protected', headers={'Authorization':'Bearer'})
    assert response.status_code == 422
    assert response.json() == {'detail': "Bad Authorization header. Expected value 'Bearer <JWT>'"}

    response = client.get('/protected', headers={'Authorization':'Bearer '})
    assert response.status_code == 422
    assert response.json() == {'detail': "Bad Authorization header. Expected value 'Bearer <JWT>'"}

def test_header_without_bearer(client):
    response = client.get('/protected', headers={'Authorization':'Test asd'})
    assert response.status_code == 422
    assert response.json() == {'detail': "Bad Authorization header. Expected value 'Bearer <JWT>'"}

    response = client.get('/protected', headers={'Authorization':'Test '})
    assert response.status_code == 422
    assert response.json() == {'detail': "Bad Authorization header. Expected value 'Bearer <JWT>'"}

def test_header_invalid_jwt(client):
    response = client.get('/protected', headers={'Authorization':'Bearer asd'})
    assert response.status_code == 422
    assert response.json() == {'detail': 'Not enough segments'}

def test_valid_header(client,Authorize):
    token = Authorize.create_access_token(identity='test')
    response = client.get('/protected',headers={'Authorization':f"Bearer {token.decode('utf-8')}"})
    assert response.status_code == 200
    assert response.json() == {'hello':'world'}

def test_jwt_custom_headers(Authorize):
    access_token = Authorize.create_access_token(identity=1,headers={'access':'bar'})
    refresh_token = Authorize.create_refresh_token(identity=2,headers={'refresh':'foo'})

    assert Authorize.get_unverified_jwt_headers(access_token)['access'] == 'bar'
    assert Authorize.get_unverified_jwt_headers(refresh_token)['refresh'] == 'foo'

def test_get_jwt_headers_from_request(client, Authorize):
    access_token = Authorize.create_access_token(identity=1,headers={'access':'bar'})
    refresh_token = Authorize.create_refresh_token(identity=2,headers={'refresh':'foo'})

    response = client.get('/get_headers_access',headers={"Authorization":f"Bearer {access_token.decode('utf-8')}"})
    assert response.json()['access'] == 'bar'

    response = client.get('/get_headers_refresh',headers={"Authorization":f"Bearer {refresh_token.decode('utf-8')}"})
    assert response.json()['refresh'] == 'foo'
