import pytest
from fastapi_jwt_auth import AuthJWT
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient

@pytest.fixture(scope='function')
def client():
    app = FastAPI()

    @app.get('/get-token')
    def get_token(Authorize: AuthJWT = Depends()):
        access_token = Authorize.create_access_token(subject=1,fresh=True)
        refresh_token = Authorize.create_refresh_token(subject=1)

        Authorize.set_access_cookies(access_token)
        Authorize.set_refresh_cookies(refresh_token)
        return {"access": access_token, "refresh": refresh_token}

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

@pytest.mark.parametrize("url",["/jwt-optional","/jwt-required","/jwt-refresh","/jwt-fresh"])
def test_get_subject_through_cookie_or_headers(url,client):
    @AuthJWT.load_config
    def get_secret_key():
        return [
            ("authjwt_secret_key","secret"),
            ("authjwt_token_location", {"headers","cookies"})
        ]

    res = client.get('/get-token')
    access_token = res.json()['access']
    refresh_token = res.json()['refresh']

    access_csrf = res.cookies.get("csrf_access_token")
    refresh_csrf = res.cookies.get("csrf_refresh_token")

    # access through headers
    if url != "/jwt-refresh":
        response = client.post(url,headers={"Authorization":f"Bearer {access_token}"})
    else:
        response = client.post(url,headers={"Authorization":f"Bearer {refresh_token}"})

    assert response.status_code == 200
    assert response.json() == {'hello': 1}

    # access through cookies
    if url != "/jwt-refresh":
        response = client.post(url,headers={"X-CSRF-Token": access_csrf})
    else:
        response = client.post(url,headers={"X-CSRF-Token": refresh_csrf})

    assert response.status_code == 200
    assert response.json() == {'hello': 1}

    AuthJWT._token_location = {"headers"}
