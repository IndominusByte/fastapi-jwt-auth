import pytest
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from typing import Optional
from pydantic import BaseSettings

@pytest.fixture(scope='function')
def client():
    app = FastAPI()

    @app.exception_handler(AuthJWTException)
    def authjwt_exception_handler(request: Request, exc: AuthJWTException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.message}
        )

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
    token = Authorize.create_access_token(subject='test')
    response = client.get('/protected',headers={'Authorization':f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {'hello':'world'}

def test_jwt_custom_headers(Authorize):
    access_token = Authorize.create_access_token(subject=1,headers={'access':'bar'})
    refresh_token = Authorize.create_refresh_token(subject=2,headers={'refresh':'foo'})

    assert Authorize.get_unverified_jwt_headers(access_token)['access'] == 'bar'
    assert Authorize.get_unverified_jwt_headers(refresh_token)['refresh'] == 'foo'

def test_get_jwt_headers_from_request(client, Authorize):
    access_token = Authorize.create_access_token(subject=1,headers={'access':'bar'})
    refresh_token = Authorize.create_refresh_token(subject=2,headers={'refresh':'foo'})

    response = client.get('/get_headers_access',headers={"Authorization":f"Bearer {access_token}"})
    assert response.json()['access'] == 'bar'

    response = client.get('/get_headers_refresh',headers={"Authorization":f"Bearer {refresh_token}"})
    assert response.json()['refresh'] == 'foo'

def test_custom_header_name(client,Authorize):
    class HeaderName(BaseSettings):
        authjwt_secret_key: str = "secret"
        authjwt_header_name: str = "Foo"

    @AuthJWT.load_config
    def get_header_name():
        return HeaderName()

    token = Authorize.create_access_token(subject=1)
    # Insure 'default' headers no longer work
    response = client.get('/protected',headers={"Authorization":f"Bearer {token}"})
    assert response.status_code == 401
    assert response.json() == {'detail': 'Missing Foo Header'}

    # Insure new headers do work
    response = client.get('/protected',headers={"Foo":f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {'hello':'world'}

    # Invalid headers
    response = client.get('/protected',headers={"Foo":"Bearer test test"})
    assert response.status_code == 422
    assert response.json() == {'detail': "Bad Foo header. Expected value 'Bearer <JWT>'"}

    AuthJWT._header_name = "Authorization"

def test_custom_header_type(client,Authorize):
    class HeaderType(BaseSettings):
        authjwt_secret_key: str = "secret"
        authjwt_header_type: str = "JWT"

    @AuthJWT.load_config
    def get_header_type():
        return HeaderType()

    token = Authorize.create_access_token(subject=1)
    # Insure 'default' headers no longer work
    response = client.get('/protected',headers={"Authorization":f"Bearer {token}"})
    assert response.status_code == 422
    assert response.json() == {'detail': "Bad Authorization header. Expected value 'JWT <JWT>'"}
    # Insure new headers do work
    response = client.get('/protected',headers={"Authorization":f"JWT {token}"})
    assert response.status_code == 200
    assert response.json() == {'hello':'world'}

    class HeaderTypeNone(BaseSettings):
        authjwt_secret_key: str = "secret"
        authjwt_header_type: Optional[str] = None

    @AuthJWT.load_config
    def get_header_type_none():
        return HeaderTypeNone()

    # Insure 'JWT' headers no longer work
    response = client.get('/protected',headers={"Authorization":f"JWT {token}"})
    assert response.status_code == 422
    assert response.json() == {'detail': "Bad Authorization header. Expected value '<JWT>'"}
    # Insure new headers without a type also work
    response = client.get('/protected',headers={"Authorization":f"{token}"})
    assert response.status_code == 200
    assert response.json() == {'hello':'world'}

    AuthJWT._header_type = "Bearer"
