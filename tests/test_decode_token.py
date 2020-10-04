import pytest, jwt, time
from .utils import reset_config
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

    @app.get('/raw_token')
    def raw_token(Authorize: AuthJWT = Depends()):
        Authorize.jwt_required()
        return Authorize.get_raw_jwt()

    @app.get('/get_identity')
    def get_identity(Authorize: AuthJWT = Depends()):
        Authorize.jwt_required()
        return Authorize.get_jwt_identity()

    client = TestClient(app)
    return client

@pytest.fixture(scope='function')
def default_access_token():
    return {
        'jti': '123',
        'identity': 'test',
        'type': 'access',
        'fresh': True,
    }

@pytest.fixture(scope='function')
def encoded_token(default_access_token):
    return jwt.encode(default_access_token,'secret-key',algorithm='HS256')

def test_verified_token(client,monkeypatch,encoded_token,Authorize):
    monkeypatch.setenv("AUTHJWT_SECRET_KEY","secret-key")
    monkeypatch.setenv("AUTHJWT_ACCESS_TOKEN_EXPIRES","1")
    reset_config()
    # DecodeError
    response = client.get('/protected',headers={"Authorization":"Bearer test"})
    assert response.status_code == 422
    assert response.json() == {'detail': 'Not enough segments'}
    # InvalidSignatureError
    token = jwt.encode({'some': 'payload'}, 'secret', algorithm='HS256')
    response = client.get('/protected',headers={"Authorization":f"Bearer {token.decode('utf-8')}"})
    assert response.status_code == 422
    assert response.json() == {'detail': 'Signature verification failed'}
    # ExpiredSignatureError
    token = Authorize.create_access_token(identity='test')
    time.sleep(2)
    response = client.get('/protected',headers={"Authorization":f"Bearer {token.decode('utf-8')}"})
    assert response.status_code == 422
    assert response.json() == {'detail': 'Signature has expired'}
    # InvalidAlgorithmError
    token = jwt.encode({'some': 'payload'}, 'secret', algorithm='HS384')
    response = client.get('/protected',headers={"Authorization":f"Bearer {token.decode('utf-8')}"})
    assert response.status_code == 422
    assert response.json() == {'detail': 'The specified alg value is not allowed'}

    response = client.get('/protected',headers={"Authorization":f"Bearer {encoded_token.decode('utf-8')}"})
    assert response.status_code == 200
    assert response.json() == {'hello':'world'}

def test_get_raw_token(client,default_access_token,encoded_token):
    response = client.get('/raw_token',headers={"Authorization":f"Bearer {encoded_token.decode('utf-8')}"})
    assert response.status_code == 200
    assert response.json() == default_access_token

def test_get_jwt_jti(client,default_access_token,encoded_token,Authorize):
    assert Authorize.get_jti(encoded_token=encoded_token) == default_access_token['jti']

def test_get_jwt_identity(client,default_access_token,encoded_token):
    response = client.get('/get_identity',headers={"Authorization":f"Bearer {encoded_token.decode('utf-8')}"})
    assert response.status_code == 200
    assert response.json() == default_access_token['identity']
