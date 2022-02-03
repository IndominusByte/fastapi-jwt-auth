import pytest
from async_fastapi_jwt_auth import AuthJWT
from async_fastapi_jwt_auth.exceptions import AuthJWTException
from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient


@pytest.fixture(scope='function')
def client():
    app = FastAPI()

    @app.exception_handler(AuthJWTException)
    def authjwt_exception_handler(request: Request, exc: AuthJWTException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.message}
        )

    @app.get('/jwt-required')
    async def jwt_required(Authorize: AuthJWT = Depends()):
        await Authorize.jwt_required()
        return {'hello': 'world'}

    @app.get('/jwt-optional')
    async def jwt_optional(Authorize: AuthJWT = Depends()):
        await Authorize.jwt_optional()
        if await Authorize.get_jwt_subject():
            return {'hello': 'world'}
        return {'hello': 'anonym'}

    @app.get('/jwt-refresh-required')
    async def jwt_refresh_required(Authorize: AuthJWT = Depends()):
        await Authorize.jwt_refresh_token_required()
        return {'hello': 'world'}

    @app.get('/fresh-jwt-required')
    async def fresh_jwt_required(Authorize: AuthJWT = Depends()):
        await Authorize.fresh_jwt_required()
        return {'hello': 'world'}

    client = TestClient(app)
    return client


@pytest.mark.parametrize("url", ["/jwt-required", "/jwt-refresh-required", "/fresh-jwt-required"])
def test_missing_header(client, url):
    response = client.get(url)
    assert response.status_code == 401
    assert response.json() == {'detail': 'Missing Authorization Header'}


@pytest.mark.parametrize("url", ["/jwt-required", "/jwt-optional", "/fresh-jwt-required"])
async def test_only_access_token_allowed(client, url, Authorize):
    token = await Authorize.create_refresh_token(subject='test')
    response = client.get(url, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 422
    assert response.json() == {'detail': 'Only access tokens are allowed'}


async def test_jwt_required(client, Authorize):
    url = '/jwt-required'
    token = await Authorize.create_access_token(subject='test')
    response = client.get(url, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {'hello': 'world'}


async def test_jwt_optional(client, Authorize):
    url = '/jwt-optional'
    # if header not define return anonym user
    response = client.get(url)
    assert response.status_code == 200
    assert response.json() == {'hello': 'anonym'}

    token = await Authorize.create_access_token(subject='test')
    response = client.get(url, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {'hello': 'world'}


async def test_refresh_required(client, Authorize):
    url = '/jwt-refresh-required'
    # only refresh token allowed
    token = await Authorize.create_access_token(subject='test')
    response = client.get(url, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 422
    assert response.json() == {'detail': 'Only refresh tokens are allowed'}

    token = await Authorize.create_refresh_token(subject='test')
    response = client.get(url, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {'hello': 'world'}


async def test_fresh_jwt_required(client, Authorize):
    url = '/fresh-jwt-required'
    # only fresh token allowed
    token = await Authorize.create_access_token(subject='test')
    response = client.get(url, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert response.json() == {'detail': 'Fresh token required'}

    token = await Authorize.create_access_token(subject='test', fresh=True)
    response = client.get(url, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {'hello': 'world'}
