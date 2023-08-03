import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from async_fastapi_jwt_auth import AuthJWT
from async_fastapi_jwt_auth.exceptions import AuthJWTException

# setting for denylist token
denylist = set()


@pytest.fixture(scope="function")
def client():
    AuthJWT._denylist_enabled = True
    AuthJWT._secret_key = "Testing_secret_not_for_real_use"

    @AuthJWT.token_in_denylist_loader
    async def check_if_token_in_denylist(decrypted_token):
        jti = decrypted_token["jti"]
        return jti in denylist

    app = FastAPI()

    @app.exception_handler(AuthJWTException)
    def authjwt_exception_handler(request: Request, exc: AuthJWTException):
        return JSONResponse(
            status_code=exc.status_code, content={"detail": exc.message}
        )

    @app.get("/jwt-required")
    async def jwt_required(Authorize: AuthJWT = Depends()):
        await Authorize.jwt_required()
        return {"hello": "world"}

    @app.get("/jwt-optional")
    async def jwt_optional(Authorize: AuthJWT = Depends()):
        await Authorize.jwt_optional()
        return {"hello": "world"}

    @app.get("/jwt-refresh-required")
    async def jwt_refresh_required(Authorize: AuthJWT = Depends()):
        await Authorize.jwt_refresh_token_required()
        return {"hello": "world"}

    @app.get("/fresh-jwt-required")
    async def fresh_jwt_required(Authorize: AuthJWT = Depends()):
        await Authorize.fresh_jwt_required()
        return {"hello": "world"}

    client = TestClient(app)
    return client


@pytest.fixture
async def access_token(Authorize):
    return await Authorize.create_access_token(subject="test", fresh=True)


@pytest.fixture
async def refresh_token(Authorize):
    return await Authorize.create_refresh_token(subject="test")


@pytest.mark.parametrize(
    "url", ["/jwt-required", "/jwt-optional", "/fresh-jwt-required"]
)
async def test_non_denylisted_access_token(client, url, access_token, Authorize):
    response = client.get(url, headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 200
    assert response.json() == {"hello": "world"}

    # revoke token in last test url
    if url == "/fresh-jwt-required":
        jti = await Authorize.get_jti(access_token)
        denylist.add(jti)


async def test_non_denylisted_refresh_token(client, refresh_token, Authorize):
    url = "/jwt-refresh-required"
    response = client.get(url, headers={"Authorization": f"Bearer {refresh_token}"})
    assert response.status_code == 200
    assert response.json() == {"hello": "world"}

    # revoke token
    jti = await Authorize.get_jti(refresh_token)
    denylist.add(jti)


@pytest.mark.parametrize(
    "url", ["/jwt-required", "/jwt-optional", "/fresh-jwt-required"]
)
async def test_denylisted_access_token(client, url, access_token, Authorize):
    # Revoke token for testing
    jti = await Authorize.get_jti(access_token)
    denylist.add(jti)

    response = client.get(url, headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Token has been revoked"}


async def test_denylisted_refresh_token(client, refresh_token, Authorize):
    # Revoke token for testing
    jti = await Authorize.get_jti(refresh_token)
    denylist.add(jti)

    url = "/jwt-refresh-required"
    response = client.get(url, headers={"Authorization": f"Bearer {refresh_token}"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Token has been revoked"}
