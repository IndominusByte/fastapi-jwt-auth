import pytest
from async_fastapi_jwt_auth import AuthJWT
from async_fastapi_jwt_auth.exceptions import AuthJWTException
from fastapi import FastAPI, Depends, WebSocket, Query
from fastapi.testclient import TestClient


@pytest.fixture(scope='function')
def client():
    app = FastAPI()

    @app.get('/all-token')
    async def all_token(Authorize: AuthJWT = Depends()):
        access_token = await Authorize.create_access_token(subject=1, fresh=True)
        refresh_token = await Authorize.create_refresh_token(subject=1)
        await Authorize.set_access_cookies(access_token)
        await Authorize.set_refresh_cookies(refresh_token)
        return {"msg": "all token"}

    @app.get('/unset-all-token')
    async def unset_all_token(Authorize: AuthJWT = Depends()):
        await Authorize.unset_jwt_cookies()
        return {"msg": "unset all token"}

    @app.websocket('/jwt-required')
    async def websocket_jwt_required(
            websocket: WebSocket,
            token: str = Query(...),
            Authorize: AuthJWT = Depends()
    ):
        await websocket.accept()
        try:
            await Authorize.jwt_required("websocket", token=token)
            await websocket.send_text("Successfully Login!")
        except AuthJWTException as err:
            await websocket.send_text(err.message)
        await websocket.close()

    @app.websocket('/jwt-required-cookies')
    async def websocket_jwt_required_cookies(
            websocket: WebSocket,
            csrf_token: str = Query(...),
            Authorize: AuthJWT = Depends()
    ):
        await websocket.accept()
        try:
            await Authorize.jwt_required("websocket", websocket=websocket, csrf_token=csrf_token)
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
            await Authorize.jwt_optional("websocket", token=token)
            decoded_token = await Authorize.get_raw_jwt(token)
            if decoded_token:
                await websocket.send_text("hello world")
            await websocket.send_text("hello anonym")
        except AuthJWTException as err:
            await websocket.send_text(err.message)
        await websocket.close()

    @app.websocket('/jwt-optional-cookies')
    async def websocket_jwt_optional_cookies(
            websocket: WebSocket,
            csrf_token: str = Query(...),
            Authorize: AuthJWT = Depends()
    ):
        await websocket.accept()
        try:
            await Authorize.jwt_optional("websocket", websocket=websocket, csrf_token=csrf_token)
            decoded_token = await Authorize.get_raw_jwt()
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
            await Authorize.jwt_refresh_token_required("websocket", token=token)
            await websocket.send_text("Successfully Login!")
        except AuthJWTException as err:
            await websocket.send_text(err.message)
        await websocket.close()

    @app.websocket('/jwt-refresh-required-cookies')
    async def websocket_jwt_refresh_required_cookies(
            websocket: WebSocket,
            csrf_token: str = Query(...),
            Authorize: AuthJWT = Depends()
    ):
        await websocket.accept()
        try:
            await Authorize.jwt_refresh_token_required("websocket", websocket=websocket, csrf_token=csrf_token)
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
            await Authorize.fresh_jwt_required("websocket", token=token)
            await websocket.send_text("Successfully Login!")
        except AuthJWTException as err:
            await websocket.send_text(err.message)
        await websocket.close()

    @app.websocket('/fresh-jwt-required-cookies')
    async def websocket_fresh_jwt_required_cookies(
            websocket: WebSocket,
            csrf_token: str = Query(...),
            Authorize: AuthJWT = Depends()
    ):
        await websocket.accept()
        try:
            await Authorize.fresh_jwt_required("websocket", websocket=websocket, csrf_token=csrf_token)
            await websocket.send_text("Successfully Login!")
        except AuthJWTException as err:
            await websocket.send_text(err.message)
        await websocket.close()

    client = TestClient(app)
    return client


@pytest.mark.parametrize("url", ["/jwt-required", "/jwt-refresh-required", "/fresh-jwt-required"])
def test_missing_token_websocket(client, url):
    token_type = "access" if url != "/jwt-refresh-required" else "refresh"
    with client.websocket_connect(url + "?token=") as websocket:
        data = websocket.receive_text()
        assert data == f"Missing {token_type} token from Query or Path"


@pytest.mark.parametrize("url", ["/jwt-required", "/jwt-optional", "/fresh-jwt-required"])
async def test_only_access_token_allowed_websocket(client, url, Authorize):
    token = await Authorize.create_refresh_token(subject='test')
    with client.websocket_connect(url + f"?token={token}") as websocket:
        data = websocket.receive_text()
        assert data == 'Only access tokens are allowed'


async def test_jwt_required_websocket(client, Authorize):
    url = '/jwt-required'
    token = await Authorize.create_access_token(subject='test')
    with client.websocket_connect(url + f"?token={token}") as websocket:
        data = websocket.receive_text()
        assert data == 'Successfully Login!'


async def test_jwt_optional_websocket(client, Authorize):
    url = '/jwt-optional'
    # if token not define return anonym user
    with client.websocket_connect(url + "?token=") as websocket:
        data = websocket.receive_text()
        assert data == "hello anonym"

    token = await Authorize.create_access_token(subject='test')
    with client.websocket_connect(url + f"?token={token}") as websocket:
        data = websocket.receive_text()
        assert data == "hello world"


async def test_refresh_required_websocket(client, Authorize):
    url = '/jwt-refresh-required'
    # only refresh token allowed
    token = await Authorize.create_access_token(subject='test')
    with client.websocket_connect(url + f"?token={token}") as websocket:
        data = websocket.receive_text()
        assert data == "Only refresh tokens are allowed"

    token = await Authorize.create_refresh_token(subject='test')
    with client.websocket_connect(url + f"?token={token}") as websocket:
        data = websocket.receive_text()
        assert data == "Successfully Login!"


async def test_fresh_jwt_required_websocket(client, Authorize):
    url = '/fresh-jwt-required'
    # only fresh token allowed
    token = await Authorize.create_access_token(subject='test')
    with client.websocket_connect(url + f"?token={token}") as websocket:
        data = websocket.receive_text()
        assert data == "Fresh token required"

    token = await Authorize.create_access_token(subject='test', fresh=True)
    with client.websocket_connect(url + f"?token={token}") as websocket:
        data = websocket.receive_text()
        assert data == "Successfully Login!"


# ========= COOKIES ========

async def test_invalid_instance_websocket(Authorize):
    with pytest.raises(TypeError, match=r"request"):
        await Authorize.jwt_required("websocket", websocket="test")
    with pytest.raises(TypeError, match=r"request"):
        await Authorize.jwt_optional("websocket", websocket="test")
    with pytest.raises(TypeError, match=r"request"):
        await Authorize.jwt_refresh_token_required("websocket", websocket="test")
    with pytest.raises(TypeError, match=r"request"):
        await Authorize.fresh_jwt_required("websocket", websocket="test")


@pytest.mark.parametrize("url",
                         ["/jwt-required-cookies", "/jwt-refresh-required-cookies", "/fresh-jwt-required-cookies"])
def test_missing_cookie(url, client):
    cookie_key = "access_token_cookie" if url != "/jwt-refresh-required-cookies" else "refresh_token_cookie"
    with client.websocket_connect(url + "?csrf_token=") as websocket:
        data = websocket.receive_text()
        assert data == f"Missing cookie {cookie_key}"


@pytest.mark.parametrize("url", [
    "/jwt-required-cookies",
    "/jwt-refresh-required-cookies",
    "/fresh-jwt-required-cookies",
    "/jwt-optional-cookies"
])
def test_missing_csrf_token(url, client):
    @AuthJWT.load_config
    def get_cookie_location():
        return [("authjwt_token_location", {'cookies'}), ("authjwt_secret_key", "secret")]

    # required and optional
    client.get('/all-token')

    with client.websocket_connect(url + "?csrf_token=") as websocket:
        data = websocket.receive_text()
        assert data == "Missing CSRF Token"

    client.get('/unset-all-token')

    # disable csrf protection
    @AuthJWT.load_config
    def change_request_csrf_protect_to_false():
        return [
            ("authjwt_token_location", {'cookies'}),
            ("authjwt_secret_key", "secret"),
            ("authjwt_cookie_csrf_protect", False)
        ]

    client.get('/all-token')

    msg = "hello world" if url == "/jwt-optional-cookies" else "Successfully Login!"
    with client.websocket_connect(url + "?csrf_token=") as websocket:
        data = websocket.receive_text()
        assert data == msg


@pytest.mark.parametrize("url", [
    "/jwt-required-cookies",
    "/jwt-refresh-required-cookies",
    "/fresh-jwt-required-cookies",
    "/jwt-optional-cookies"
])
def test_missing_claim_csrf_in_token(url, client):
    # required and optional
    @AuthJWT.load_config
    def change_request_csrf_protect_to_false():
        return [
            ("authjwt_token_location", {'cookies'}),
            ("authjwt_secret_key", "secret"),
            ("authjwt_cookie_csrf_protect", False)
        ]

    client.get('/all-token')

    @AuthJWT.load_config
    def change_request_csrf_protect_to_true():
        return [("authjwt_token_location", {'cookies'}), ("authjwt_secret_key", "secret")]

    with client.websocket_connect(url + "?csrf_token=test") as websocket:
        data = websocket.receive_text()
        assert data == "Missing claim: csrf"

    # disable csrf protection
    @AuthJWT.load_config
    def change_request_csrf_protect_to_false_again():
        return [
            ("authjwt_token_location", {'cookies'}),
            ("authjwt_secret_key", "secret"),
            ("authjwt_cookie_csrf_protect", False)
        ]

    msg = "hello world" if url == "/jwt-optional-cookies" else "Successfully Login!"
    with client.websocket_connect(url + "?csrf_token=test") as websocket:
        data = websocket.receive_text()
        assert data == msg


@pytest.mark.parametrize("url", [
    "/jwt-required-cookies",
    "/jwt-refresh-required-cookies",
    "/fresh-jwt-required-cookies",
    "/jwt-optional-cookies"
])
def test_invalid_csrf_double_submit(url, client):
    # required and optional
    @AuthJWT.load_config
    def get_cookie_location():
        return [("authjwt_token_location", {'cookies'}), ("authjwt_secret_key", "secret")]

    client.get('/all-token')

    with client.websocket_connect(url + "?csrf_token=test") as websocket:
        data = websocket.receive_text()
        assert data == "CSRF double submit tokens do not match"

    # disable csrf protection
    @AuthJWT.load_config
    def change_request_csrf_protect_to_false():
        return [
            ("authjwt_token_location", {'cookies'}),
            ("authjwt_secret_key", "secret"),
            ("authjwt_cookie_csrf_protect", False)
        ]

    msg = "hello world" if url == "/jwt-optional-cookies" else "Successfully Login!"
    with client.websocket_connect(url + "?csrf_token=test") as websocket:
        data = websocket.receive_text()
        assert data == msg


@pytest.mark.parametrize("url", [
    "/jwt-required-cookies",
    "/jwt-refresh-required-cookies",
    "/fresh-jwt-required-cookies",
    "/jwt-optional-cookies"
])
def test_valid_access_endpoint_with_csrf(url, client):
    # required and optional
    @AuthJWT.load_config
    def get_cookie_location():
        return [("authjwt_token_location", {'cookies'}), ("authjwt_secret_key", "secret")]

    res = client.get('/all-token')
    csrf_access = res.cookies.get("csrf_access_token")
    csrf_refresh = res.cookies.get("csrf_refresh_token")

    if url == "/jwt-refresh-required-cookies":
        with client.websocket_connect(url + f"?csrf_token={csrf_refresh}") as websocket:
            data = websocket.receive_text()
            assert data == "Successfully Login!"
    else:
        msg = "hello world" if url == "/jwt-optional-cookies" else "Successfully Login!"
        with client.websocket_connect(url + f"?csrf_token={csrf_access}") as websocket:
            data = websocket.receive_text()
            assert data == msg
