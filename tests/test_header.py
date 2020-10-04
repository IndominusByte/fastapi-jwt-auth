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
