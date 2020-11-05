import pytest
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from fastapi import FastAPI, Depends, WebSocket, Query
from fastapi.testclient import TestClient

@pytest.fixture(scope='function')
def client():
    app = FastAPI()

    @app.websocket('/jwt-required')
    async def websocket_jwt_required(
        websocket: WebSocket,
        token: str = Query(...),
        Authorize: AuthJWT = Depends()
    ):
        await websocket.accept()
        try:
            Authorize.jwt_required("websocket",token=token)
            await websocket.send_text("Successfully Login!")
        except AuthJWTException as err:
            await websocket.send_text(err.message)
        await websocket.close()

    @app.websocket('/jwt-optional')
    async def websocket_jwt_optional(
        websocket: WebSocket,
        token: str = Query(...),
        Authorize: AuthJWT = Depends()
    ):
        await websocket.accept()
        try:
            Authorize.jwt_optional("websocket",token=token)
            decoded_token = Authorize.get_raw_jwt(token)
            if decoded_token:
                await websocket.send_text("hello world")
            await websocket.send_text("hello anonym")
        except AuthJWTException as err:
            await websocket.send_text(err.message)
        await websocket.close()

    @app.websocket('/jwt-refresh-required')
    async def websocket_jwt_refresh_required(
        websocket: WebSocket,
        token: str = Query(...),
        Authorize: AuthJWT = Depends()
    ):
        await websocket.accept()
        try:
            Authorize.jwt_refresh_token_required("websocket",token=token)
            await websocket.send_text("Successfully Login!")
        except AuthJWTException as err:
            await websocket.send_text(err.message)
        await websocket.close()

    @app.websocket('/fresh-jwt-required')
    async def websocket_fresh_jwt_required(
        websocket: WebSocket,
        token: str = Query(...),
        Authorize: AuthJWT = Depends()
    ):
        await websocket.accept()
        try:
            Authorize.fresh_jwt_required("websocket",token=token)
            await websocket.send_text("Successfully Login!")
        except AuthJWTException as err:
            await websocket.send_text(err.message)
        await websocket.close()

    client = TestClient(app)
    return client

@pytest.mark.parametrize("url",["/jwt-required","/jwt-refresh-required","/fresh-jwt-required"])
def test_missing_token_websocket(client,url):
    token_type = "access" if url != "/jwt-refresh-required" else "refresh"
    with client.websocket_connect(url + "?token=") as websocket:
        data = websocket.receive_text()
        assert data == f"Missing {token_type} token from Query or Path"

@pytest.mark.parametrize("url",["/jwt-required","/jwt-optional","/fresh-jwt-required"])
def test_only_access_token_allowed_websocket(client,url,Authorize):
    token = Authorize.create_refresh_token(subject='test')
    with client.websocket_connect(url + f"?token={token}") as websocket:
        data = websocket.receive_text()
        assert data == 'Only access tokens are allowed'

def test_jwt_required_websocket(client,Authorize):
    url = '/jwt-required'
    token = Authorize.create_access_token(subject='test')
    with client.websocket_connect(url + f"?token={token}") as websocket:
        data = websocket.receive_text()
        assert data == 'Successfully Login!'

def test_jwt_optional_websocket(client,Authorize):
    url = '/jwt-optional'
    # if token not define return anonym user
    with client.websocket_connect(url + "?token=") as websocket:
        data = websocket.receive_text()
        assert data == "hello anonym"

    token = Authorize.create_access_token(subject='test')
    with client.websocket_connect(url + f"?token={token}") as websocket:
        data = websocket.receive_text()
        assert data == "hello world"

def test_refresh_required_websocket(client,Authorize):
    url = '/jwt-refresh-required'
    # only refresh token allowed
    token = Authorize.create_access_token(subject='test')
    with client.websocket_connect(url + f"?token={token}") as websocket:
        data = websocket.receive_text()
        assert data == "Only refresh tokens are allowed"

    token = Authorize.create_refresh_token(subject='test')
    with client.websocket_connect(url + f"?token={token}") as websocket:
        data = websocket.receive_text()
        assert data == "Successfully Login!"

def test_fresh_jwt_required_websocket(client,Authorize):
    url = '/fresh-jwt-required'
    # only fresh token allowed
    token = Authorize.create_access_token(subject='test')
    with client.websocket_connect(url + f"?token={token}") as websocket:
        data = websocket.receive_text()
        assert data == "Fresh token required"

    token = Authorize.create_access_token(subject='test',fresh=True)
    with client.websocket_connect(url + f"?token={token}") as websocket:
        data = websocket.receive_text()
        assert data == "Successfully Login!"
