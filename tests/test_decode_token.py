import pytest, jwt, time
from fastapi_jwt_auth import AuthJWT
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from pydantic import BaseSettings

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

    @app.get('/refresh_token')
    def get_refresh_token(Authorize: AuthJWT = Depends()):
        Authorize.jwt_refresh_token_required()
        return Authorize.get_jwt_identity()

    client = TestClient(app)
    return client

@pytest.fixture(scope='function')
def default_access_token():
    return {
        'jti': '123',
        'user': {
            'identity': 'test',
            'type': 'access',
            'fresh': True,
        }
    }

@pytest.fixture(scope='function')
def encoded_token(default_access_token):
    return jwt.encode(default_access_token,'secret-key',algorithm='HS256')

def test_verified_token(client,encoded_token,Authorize):
    class SettingsOne(BaseSettings):
        AUTHJWT_SECRET_KEY: str = "secret-key"
        AUTHJWT_ACCESS_TOKEN_EXPIRES: int = 1

    @AuthJWT.load_config
    def get_settings_one():
        return SettingsOne()

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

    class SettingsTwo(BaseSettings):
        AUTHJWT_SECRET_KEY: str = "secret-key"
        AUTHJWT_ACCESS_TOKEN_EXPIRES: int = 1
        AUTHJWT_REFRESH_TOKEN_EXPIRES: int = 1
        AUTHJWT_DECODE_LEEWAY: int = 2

    @AuthJWT.load_config
    def get_settings_two():
        return SettingsTwo()

    access_token = Authorize.create_access_token(identity='test')
    refresh_token = Authorize.create_refresh_token(identity='test')
    time.sleep(2)
    # JWT payload is now expired
    # But with some leeway, it will still validate
    response = client.get('/protected',headers={"Authorization":f"Bearer {access_token.decode('utf-8')}"})
    assert response.status_code == 200
    assert response.json() == {'hello':'world'}

    response = client.get('/refresh_token',headers={"Authorization":f"Bearer {refresh_token.decode('utf-8')}"})
    assert response.status_code == 200
    assert response.json() == "test"

    # Valid Token
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
    assert response.json() == default_access_token['user']['identity']
