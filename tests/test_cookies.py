import pytest
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from fastapi import FastAPI, Request, Depends
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

    @app.get('/all-token')
    def all_token(Authorize: AuthJWT = Depends()):
        access_token = Authorize.create_access_token(subject=1,fresh=True)
        refresh_token = Authorize.create_refresh_token(subject=1)
        Authorize.set_access_cookies(access_token)
        Authorize.set_refresh_cookies(refresh_token)
        return {"msg":"all token"}

    @app.get('/all-token-response')
    def all_token_response(Authorize: AuthJWT = Depends()):
        access_token = Authorize.create_access_token(subject=1,fresh=True)
        refresh_token = Authorize.create_refresh_token(subject=1)
        response = JSONResponse(content={"msg":"all token"})
        Authorize.set_access_cookies(access_token,response)
        Authorize.set_refresh_cookies(refresh_token,response)
        return response

    @app.get('/access-token')
    def access_token(Authorize: AuthJWT = Depends()):
        access_token = Authorize.create_access_token(subject=1)
        Authorize.set_access_cookies(access_token)
        return {"msg":"access token"}

    @app.get('/access-token-response')
    def access_token_response(Authorize: AuthJWT = Depends()):
        access_token = Authorize.create_access_token(subject=1)
        response = JSONResponse(content={"msg":"access token"})
        Authorize.set_access_cookies(access_token,response)
        return response

    @app.get('/refresh-token')
    def refresh_token(Authorize: AuthJWT = Depends()):
        refresh_token = Authorize.create_refresh_token(subject=1)
        Authorize.set_refresh_cookies(refresh_token)
        return {"msg":"refresh token"}

    @app.get('/refresh-token-response')
    def refresh_token_response(Authorize: AuthJWT = Depends()):
        refresh_token = Authorize.create_refresh_token(subject=1)
        response = JSONResponse(content={"msg":"refresh token"})
        Authorize.set_refresh_cookies(refresh_token,response)
        return response

    @app.get('/unset-all-token')
    def unset_all_token(Authorize: AuthJWT = Depends()):
        Authorize.unset_jwt_cookies()
        return {"msg":"unset all token"}

    @app.get('/unset-all-token-response')
    def unset_all_token_response(Authorize: AuthJWT = Depends()):
        response = JSONResponse(content={"msg":"unset all token"})
        Authorize.unset_jwt_cookies(response)
        return response

    @app.get('/unset-access-token')
    def unset_access_token(Authorize: AuthJWT = Depends()):
        Authorize.unset_access_cookies()

    @app.get('/unset-refresh-token')
    def unset_refresh_token(Authorize: AuthJWT = Depends()):
        Authorize.unset_refresh_cookies()

    @app.post('/jwt-optional')
    def jwt_optional(Authorize: AuthJWT = Depends()):
        Authorize.jwt_optional()
        return {"hello": Authorize.get_jwt_subject()}

    @app.post('/jwt-required')
    def jwt_required(Authorize: AuthJWT = Depends()):
        Authorize.jwt_required()
        return {"hello": Authorize.get_jwt_subject()}

    @app.post('/jwt-refresh')
    def jwt_refresh(Authorize: AuthJWT = Depends()):
        Authorize.jwt_refresh_token_required()
        return {"hello": Authorize.get_jwt_subject()}

    @app.post('/jwt-fresh')
    def jwt_fresh(Authorize: AuthJWT = Depends()):
        Authorize.fresh_jwt_required()
        return {"hello": Authorize.get_jwt_subject()}

    client = TestClient(app)
    return client

@pytest.mark.parametrize(
    "url",["/access-token","/refresh-token","/unset-access-token","/unset-refresh-token"]
)
def test_warning_if_cookies_not_in_token_location(url,client):
    @AuthJWT.load_config
    def get_secret_key():
        return [("authjwt_secret_key","secret")]

    with pytest.raises(RuntimeWarning,match=r"authjwt_token_location"):
        client.get(url)

def test_set_cookie_not_valid_type_max_age(Authorize):
    @AuthJWT.load_config
    def get_cookie_location():
        return [("authjwt_token_location",{'cookies'}),("authjwt_secret_key","secret")]

    token = Authorize.create_access_token(subject=1)

    with pytest.raises(TypeError,match=r"max_age"):
        Authorize.set_access_cookies(token,max_age="string")

    with pytest.raises(TypeError,match=r"max_age"):
        Authorize.set_refresh_cookies(token,max_age="string")

def test_set_unset_cookies_not_valid_type_response(Authorize):
    @AuthJWT.load_config
    def get_cookie_location():
        return [("authjwt_token_location",{'cookies'}),("authjwt_secret_key","secret")]

    token = Authorize.create_access_token(subject=1)

    with pytest.raises(TypeError,match=r"response"):
        Authorize.set_access_cookies(token,response={"msg":"hello"})

    with pytest.raises(TypeError,match=r"response"):
        Authorize.set_refresh_cookies(token,response={"msg":"hello"})

    with pytest.raises(TypeError,match=r"response"):
        Authorize.unset_jwt_cookies({"msg":"hello"})

    with pytest.raises(TypeError,match=r"response"):
        Authorize.unset_access_cookies({"msg":"hello"})

    with pytest.raises(TypeError,match=r"response"):
        Authorize.unset_refresh_cookies({"msg":"hello"})

@pytest.mark.parametrize("url",["/access-token","/refresh-token","/access-token-response","/refresh-token-response"])
def test_set_cookie_csrf_protect_false(url,client):
    @AuthJWT.load_config
    def get_cookie_location():
        return [
            ("authjwt_token_location",{'cookies'}),
            ("authjwt_secret_key","secret"),
            ("authjwt_cookie_csrf_protect",False)
        ]

    cookie_key = url.split("-")[0][1:]
    response = client.get(url)
    assert response.cookies.get("csrf_{}_token".format(cookie_key)) is None

@pytest.mark.parametrize("url",["/access-token","/refresh-token","/access-token-response","/refresh-token-response"])
def test_set_cookie_csrf_protect_true(url,client):
    @AuthJWT.load_config
    def get_cookie_location():
        return [("authjwt_token_location",{'cookies'}),("authjwt_secret_key","secret")]

    cookie_key = url.split("-")[0][1:]
    response = client.get(url)
    assert response.cookies.get("csrf_{}_token".format(cookie_key)) is not None

def test_unset_all_cookie(client):
    @AuthJWT.load_config
    def get_cookie_location():
        return [("authjwt_token_location",{'cookies'}),("authjwt_secret_key","secret")]

    response = client.get('/all-token')
    assert response.cookies.get("access_token_cookie") is not None
    assert response.cookies.get("csrf_access_token") is not None

    assert response.cookies.get("refresh_token_cookie") is not None
    assert response.cookies.get("csrf_refresh_token") is not None

    response = client.get('/unset-all-token')

    assert response.cookies.get("access_token_cookie") is None
    assert response.cookies.get("csrf_access_token") is None

    assert response.cookies.get("refresh_token_cookie") is None
    assert response.cookies.get("csrf_refresh_token") is None

def test_unset_all_cookie_response(client):
    @AuthJWT.load_config
    def get_cookie_location():
        return [("authjwt_token_location",{'cookies'}),("authjwt_secret_key","secret")]

    response = client.get('/all-token-response')
    assert response.cookies.get("access_token_cookie") is not None
    assert response.cookies.get("csrf_access_token") is not None

    assert response.cookies.get("refresh_token_cookie") is not None
    assert response.cookies.get("csrf_refresh_token") is not None

    response = client.get('/unset-all-token-response')

    assert response.cookies.get("access_token_cookie") is None
    assert response.cookies.get("csrf_access_token") is None

    assert response.cookies.get("refresh_token_cookie") is None
    assert response.cookies.get("csrf_refresh_token") is None

def test_custom_cookie_key(client):
    @AuthJWT.load_config
    def get_cookie_location():
        return [
            ("authjwt_token_location",{'cookies'}),
            ("authjwt_secret_key","secret"),
            ("authjwt_access_cookie_key","access_cookie"),
            ("authjwt_refresh_cookie_key","refresh_cookie"),
            ("authjwt_access_csrf_cookie_key","csrf_access"),
            ("authjwt_refresh_csrf_cookie_key","csrf_refresh")
        ]

    response = client.get('/all-token')
    assert response.cookies.get("access_cookie") is not None
    assert response.cookies.get("csrf_access") is not None

    assert response.cookies.get("refresh_cookie") is not None
    assert response.cookies.get("csrf_refresh") is not None

    response = client.get('/unset-all-token')

    assert response.cookies.get("access_cookie") is None
    assert response.cookies.get("csrf_access") is None

    assert response.cookies.get("refresh_cookie") is None
    assert response.cookies.get("csrf_refresh") is None

def test_cookie_optional_protected(client):
    @AuthJWT.load_config
    def get_cookie_location():
        return [("authjwt_token_location",{'cookies'}),("authjwt_secret_key","secret")]

    url = '/jwt-optional'
    # without token
    response = client.post(url)
    assert response.status_code == 200
    assert response.json() == {'hello': None}

    # change request methods and not check csrf token
    @AuthJWT.load_config
    def change_request_methods():
        return [
            ("authjwt_csrf_methods",{"GET"}),
            ("authjwt_token_location",{'cookies'}),
            ("authjwt_secret_key","secret")
        ]

    client.get('/access-token')
    response = client.post(url)
    assert response.status_code == 200
    assert response.json() == {'hello': 1}

    # change csrf protect to False not check csrf token
    @AuthJWT.load_config
    def change_request_csrf_protect_to_false():
        return [
            ("authjwt_csrf_methods",{'POST','PUT','PATCH','DELETE'}),
            ("authjwt_token_location",{'cookies'}),
            ("authjwt_secret_key","secret"),
            ("authjwt_cookie_csrf_protect",False)
        ]

    client.get('/access-token')
    response = client.post(url)
    assert response.status_code == 200
    assert response.json() == {'hello': 1}

    # missing csrf token
    @AuthJWT.load_config
    def change_csrf_protect_to_true():
        return [
            ("authjwt_token_location",{'cookies'}),
            ("authjwt_secret_key","secret"),
            ("authjwt_cookie_csrf_protect",True)
        ]

    res = client.get('/access-token')
    csrf_token = res.cookies.get("csrf_access_token")

    response = client.post(url)
    assert response.status_code == 401
    assert response.json() == {'detail': 'Missing CSRF Token'}

    # csrf token do not match
    response = client.post(url,headers={"X-CSRF-Token":"invalid"})
    assert response.status_code == 401
    assert response.json() == {'detail': 'CSRF double submit tokens do not match'}

    response = client.post(url,headers={"X-CSRF-Token": csrf_token})
    assert response.status_code == 200
    assert response.json() == {'hello': 1}

    # missing claim csrf in token
    @AuthJWT.load_config
    def change_request_csrf_protect_to_falsee():
        return [
            ("authjwt_token_location",{'cookies'}),
            ("authjwt_secret_key","secret"),
            ("authjwt_cookie_csrf_protect",False)
        ]

    client.get('/access-token')

    @AuthJWT.load_config
    def change_request_csrf_protect_to_truee():
        return [("authjwt_token_location",{'cookies'}),("authjwt_secret_key","secret")]

    response = client.post(url,headers={"X-CSRF-Token":"invalid"})
    assert response.status_code == 422
    assert response.json() == {'detail': 'Missing claim: csrf'}

    # custom csrf header name and cookie key
    @AuthJWT.load_config
    def custom_header_name_cookie_key():
        return [
            ("authjwt_token_location",{'cookies'}),
            ("authjwt_secret_key","secret"),
            ("authjwt_access_cookie_key","access_cookie"),
            ("authjwt_access_csrf_header_name","X-CSRF")
        ]

    res = client.get('/access-token')
    csrf_token = res.cookies.get("csrf_access_token")

    # valid request
    response = client.post(url,headers={"X-CSRF": csrf_token})
    assert response.status_code == 200
    assert response.json() == {'hello': 1}

@pytest.mark.parametrize("url",["/jwt-required","/jwt-refresh","/jwt-fresh"])
def test_cookie_protected(url,client):
    # custom csrf header name and cookie key
    @AuthJWT.load_config
    def custom_header_name_cookie_key():
        return [
            ("authjwt_token_location",{'cookies'}),
            ("authjwt_secret_key","secret"),
            ("authjwt_access_cookie_key","access_cookie"),
            ("authjwt_access_csrf_header_name","X-CSRF-Access"),
            ("authjwt_refresh_cookie_key","refresh_cookie"),
            ("authjwt_refresh_csrf_header_name","X-CSRF-Refresh")
        ]

    res = client.get('/all-token')
    csrf_access = res.cookies.get("csrf_access_token")
    csrf_refresh = res.cookies.get("csrf_refresh_token")

    if url != "/jwt-refresh":
        response = client.post(url,headers={"X-CSRF-Access": csrf_access})
    else:
        response = client.post(url,headers={"X-CSRF-Refresh": csrf_refresh})

    assert response.status_code == 200
    assert response.json() == {'hello': 1}

    # missing csrf token
    response = client.post(url)
    assert response.status_code == 401
    assert response.json() == {'detail': 'Missing CSRF Token'}

    # missing cookie
    client.get('/unset-all-token')
    response = client.post(url)
    assert response.status_code == 401
    if url != "/jwt-refresh":
        assert response.json() == {'detail': 'Missing cookie access_cookie'}
    else:
        assert response.json() == {'detail': 'Missing cookie refresh_cookie'}

    # change csrf protect to False not check csrf token
    @AuthJWT.load_config
    def change_request_csrf_protect_to_false():
        return [
            ("authjwt_token_location",{'cookies'}),
            ("authjwt_secret_key","secret"),
            ("authjwt_cookie_csrf_protect",False)
        ]

    client.get('/all-token')
    response = client.post(url)
    assert response.status_code == 200
    assert response.json() == {'hello': 1}

    # change request methods and not check csrf token
    @AuthJWT.load_config
    def change_request_methods():
        return [
            ("authjwt_csrf_methods",{"GET"}),
            ("authjwt_token_location",{'cookies'}),
            ("authjwt_secret_key","secret"),
            ("authjwt_cookie_csrf_protect",True)
        ]

    response = client.post(url)
    assert response.status_code == 200
    assert response.json() == {'hello': 1}

    # missing claim csrf in token
    @AuthJWT.load_config
    def change_request_methods_to_default():
        return [
            ("authjwt_csrf_methods",{'POST','PUT','PATCH','DELETE'}),
            ("authjwt_token_location",{'cookies'}),
            ("authjwt_secret_key","secret"),
        ]

    response = client.post(url,headers={"X-CSRF-Token":"invalid"})
    assert response.status_code == 422
    assert response.json() == {'detail': 'Missing claim: csrf'}

    # csrf token do not match
    res = client.get('/all-token')
    csrf_access = res.cookies.get("csrf_access_token")
    csrf_refresh = res.cookies.get("csrf_refresh_token")

    response = client.post(url,headers={"X-CSRF-Token":"invalid"})
    assert response.status_code == 401
    assert response.json() == {'detail': 'CSRF double submit tokens do not match'}

    # valid request
    if url != "/jwt-refresh":
        response = client.post(url,headers={"X-CSRF-Token": csrf_access})
    else:
        response = client.post(url,headers={"X-CSRF-Token": csrf_refresh})
    assert response.status_code == 200
    assert response.json() == {'hello': 1}
