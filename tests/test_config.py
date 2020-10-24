import pytest, os, jwt
from fastapi_jwt_auth import AuthJWT
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from pydantic import BaseSettings, ValidationError
from typing import Sequence, Optional
from datetime import timedelta

@pytest.fixture(scope='function')
def client():
    app = FastAPI()

    @app.get('/protected')
    def protected(Authorize: AuthJWT = Depends()):
        Authorize.jwt_required()

    client = TestClient(app)
    return client

def test_default_config():
    assert AuthJWT._token is None
    assert AuthJWT._token_location == {'headers'}
    assert AuthJWT._response is None
    assert AuthJWT._request is None
    assert AuthJWT._secret_key is None
    assert AuthJWT._public_key is None
    assert AuthJWT._private_key is None
    assert AuthJWT._algorithm == 'HS256'
    assert AuthJWT._decode_algorithms is None
    assert AuthJWT._decode_leeway == 0
    assert AuthJWT._encode_issuer is None
    assert AuthJWT._decode_issuer is None
    assert AuthJWT._decode_audience is None
    assert AuthJWT._denylist_enabled is False
    assert AuthJWT._denylist_token_checks == {'access','refresh'}
    assert AuthJWT._token_in_denylist_callback is None
    assert AuthJWT._header_name == "Authorization"
    assert AuthJWT._header_type == "Bearer"

    assert AuthJWT._access_token_expires.__class__ == timedelta
    assert int(AuthJWT._access_token_expires.total_seconds()) == 900

    assert AuthJWT._refresh_token_expires.__class__ == timedelta
    assert int(AuthJWT._refresh_token_expires.total_seconds()) == 2592000
    # option for create cookies
    assert AuthJWT._access_cookie_key == "access_token_cookie"
    assert AuthJWT._refresh_cookie_key == "refresh_token_cookie"
    assert AuthJWT._access_cookie_path == "/"
    assert AuthJWT._refresh_cookie_path == "/"
    assert AuthJWT._cookie_max_age is None
    assert AuthJWT._cookie_domain is None
    assert AuthJWT._cookie_secure is False
    assert AuthJWT._cookie_samesite is None
    # option for double submit csrf protection
    assert AuthJWT._cookie_csrf_protect is True
    assert AuthJWT._access_csrf_cookie_key == "csrf_access_token"
    assert AuthJWT._refresh_csrf_cookie_key == "csrf_refresh_token"
    assert AuthJWT._access_csrf_cookie_path == "/"
    assert AuthJWT._refresh_csrf_cookie_path == "/"
    assert AuthJWT._access_csrf_header_name == "X-CSRF-Token"
    assert AuthJWT._refresh_csrf_header_name == "X-CSRF-Token"
    assert AuthJWT._csrf_methods == {'POST','PUT','PATCH','DELETE'}

def test_token_expired_false(Authorize):
    class TokenFalse(BaseSettings):
        authjwt_secret_key: str = "testing"
        authjwt_access_token_expires: bool = False
        authjwt_refresh_token_expires: bool = False

    @AuthJWT.load_config
    def get_expired_false():
        return TokenFalse()

    access_token = Authorize.create_access_token(subject=1)
    assert 'exp' not in jwt.decode(access_token,"testing",algorithms="HS256")

    refresh_token = Authorize.create_refresh_token(subject=1)
    assert 'exp' not in jwt.decode(refresh_token,"testing",algorithms="HS256")

def test_secret_key_not_exist(client,Authorize):
    AuthJWT._secret_key = None

    with pytest.raises(RuntimeError,match=r"authjwt_secret_key"):
        Authorize.create_access_token(subject='test')

    Authorize._secret_key = "secret"
    token = Authorize.create_access_token(subject=1)
    Authorize._secret_key = None

    with pytest.raises(RuntimeError,match=r"authjwt_secret_key"):
        client.get('/protected',headers={"Authorization":f"Bearer {token}"})

def test_denylist_enabled_without_callback(client):
    # set authjwt_secret_key for create token
    class SettingsOne(BaseSettings):
        authjwt_secret_key: str = "secret-key"
        # AuthJWT denylist won't trigger if value not True
        authjwt_denylist_enabled: bool = False

    @AuthJWT.load_config
    def get_settings_one():
        return SettingsOne()

    Authorize = AuthJWT()

    token = Authorize.create_access_token(subject='test')

    response = client.get('/protected',headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200

    class SettingsTwo(BaseSettings):
        authjwt_secret_key: str = "secret-key"
        authjwt_denylist_enabled: bool = True
        authjwt_denylist_token_checks: list = ["access"]

    @AuthJWT.load_config
    def get_settings_two():
        return SettingsTwo()

    with pytest.raises(RuntimeError,match=r"@AuthJWT.token_in_denylist_loader"):
        response = client.get('/protected',headers={"Authorization": f"Bearer {token}"})

def test_load_env_from_outside():
    DIR = os.path.abspath(os.path.dirname(__file__))
    private_txt = os.path.join(DIR,'private_key.txt')
    public_txt = os.path.join(DIR,'public_key.txt')

    with open(private_txt) as f:
        PRIVATE_KEY = f.read().strip()

    with open(public_txt) as f:
        PUBLIC_KEY = f.read().strip()

    # correct data
    class Settings(BaseSettings):
        authjwt_token_location: list = ['cookies']
        authjwt_secret_key: str = "testing"
        authjwt_public_key: str = PUBLIC_KEY
        authjwt_private_key: str = PRIVATE_KEY
        authjwt_algorithm: str = "HS256"
        authjwt_decode_algorithms: list = ['HS256']
        authjwt_decode_leeway: timedelta = timedelta(seconds=8)
        authjwt_encode_issuer: str = "urn:foo"
        authjwt_decode_issuer: str = "urn:foo"
        authjwt_decode_audience: str = 'urn:foo'
        authjwt_denylist_token_checks: Sequence = ['refresh']
        authjwt_denylist_enabled: bool = False
        authjwt_header_name: str = "Auth-Token"
        authjwt_header_type: Optional[str] = None
        authjwt_access_token_expires: timedelta = timedelta(minutes=2)
        authjwt_refresh_token_expires: timedelta = timedelta(days=5)
        # option for create cookies
        authjwt_access_cookie_key: str = "access_cookie"
        authjwt_refresh_cookie_key: str = "refresh_cookie"
        authjwt_access_cookie_path: str = "/access-cookie"
        authjwt_refresh_cookie_path: str = "/refresh-cookie"
        authjwt_cookie_max_age: int = 90
        authjwt_cookie_domain: str = "example.com"
        authjwt_cookie_secure: bool = True
        authjwt_cookie_samesite: str = "strict"
        # option for double submit csrf protection
        authjwt_cookie_csrf_protect: bool = False
        authjwt_access_csrf_cookie_key: str = "csrf_access"
        authjwt_refresh_csrf_cookie_key: str = "csrf_refresh"
        authjwt_access_csrf_cookie_path: str = "/access-csrf"
        authjwt_refresh_csrf_cookie_path: str = "/refresh-csrf"
        authjwt_access_csrf_header_name: str = "ACCESS-CSRF-Token"
        authjwt_refresh_csrf_header_name: str = "REFRESH-CSRF-Token"
        authjwt_csrf_methods: list = ['post']

    @AuthJWT.load_config
    def get_valid_settings():
        return Settings()

    assert AuthJWT._token_location == ['cookies']
    assert AuthJWT._secret_key == "testing"
    assert AuthJWT._public_key == PUBLIC_KEY
    assert AuthJWT._private_key == PRIVATE_KEY
    assert AuthJWT._algorithm == "HS256"
    assert AuthJWT._decode_algorithms == ['HS256']
    assert AuthJWT._decode_leeway == timedelta(seconds=8)
    assert AuthJWT._encode_issuer == "urn:foo"
    assert AuthJWT._decode_issuer == "urn:foo"
    assert AuthJWT._decode_audience == 'urn:foo'
    assert AuthJWT._denylist_token_checks == ['refresh']
    assert AuthJWT._denylist_enabled is False
    assert AuthJWT._header_name == "Auth-Token"
    assert AuthJWT._header_type is None
    assert AuthJWT._access_token_expires == timedelta(minutes=2)
    assert AuthJWT._refresh_token_expires == timedelta(days=5)
    # option for create cookies
    assert AuthJWT._access_cookie_key == "access_cookie"
    assert AuthJWT._refresh_cookie_key == "refresh_cookie"
    assert AuthJWT._access_cookie_path == "/access-cookie"
    assert AuthJWT._refresh_cookie_path == "/refresh-cookie"
    assert AuthJWT._cookie_max_age == 90
    assert AuthJWT._cookie_domain == "example.com"
    assert AuthJWT._cookie_secure is True
    assert AuthJWT._cookie_samesite == "strict"
    # option for double submit csrf protection
    assert AuthJWT._cookie_csrf_protect is False
    assert AuthJWT._access_csrf_cookie_key == "csrf_access"
    assert AuthJWT._refresh_csrf_cookie_key == "csrf_refresh"
    assert AuthJWT._access_csrf_cookie_path == "/access-csrf"
    assert AuthJWT._refresh_csrf_cookie_path == "/refresh-csrf"
    assert AuthJWT._access_csrf_header_name == "ACCESS-CSRF-Token"
    assert AuthJWT._refresh_csrf_header_name == "REFRESH-CSRF-Token"
    assert AuthJWT._csrf_methods == ['POST']

    with pytest.raises(TypeError,match=r"Config"):
        @AuthJWT.load_config
        def invalid_data():
            return "test"

    with pytest.raises(ValidationError,match=r"authjwt_token_location"):
        @AuthJWT.load_config
        def get_invalid_token_location_type():
            return [("authjwt_token_location",1)]

    with pytest.raises(ValidationError,match=r"authjwt_token_location"):
        @AuthJWT.load_config
        def get_invalid_token_location_value():
            return [("authjwt_token_location",{"headers","cookie"})]

    with pytest.raises(ValidationError,match=r"authjwt_secret_key"):
        @AuthJWT.load_config
        def get_invalid_secret_key():
            return [("authjwt_secret_key",123)]

    with pytest.raises(ValidationError,match=r"authjwt_public_key"):
        @AuthJWT.load_config
        def get_invalid_public_key():
            return [("authjwt_public_key",123)]

    with pytest.raises(ValidationError,match=r"authjwt_private_key"):
        @AuthJWT.load_config
        def get_invalid_private_key():
            return [("authjwt_private_key",123)]

    with pytest.raises(ValidationError,match=r"authjwt_algorithm"):
        @AuthJWT.load_config
        def get_invalid_algorithm():
            return [("authjwt_algorithm",123)]

    with pytest.raises(ValidationError,match=r"authjwt_decode_algorithms"):
        @AuthJWT.load_config
        def get_invalid_decode_algorithms():
            return [("authjwt_decode_algorithms","test")]

    with pytest.raises(ValidationError,match=r"authjwt_decode_leeway"):
        @AuthJWT.load_config
        def get_invalid_decode_leeway():
            return [("authjwt_decode_leeway","test")]

    with pytest.raises(ValidationError,match=r"authjwt_encode_issuer"):
        @AuthJWT.load_config
        def get_invalid_encode_issuer():
            return [("authjwt_encode_issuer",1)]

    with pytest.raises(ValidationError,match=r"authjwt_decode_issuer"):
        @AuthJWT.load_config
        def get_invalid_decode_issuer():
            return [("authjwt_decode_issuer",1)]

    with pytest.raises(ValidationError,match=r"authjwt_decode_audience"):
        @AuthJWT.load_config
        def get_invalid_decode_audience():
            return [("authjwt_decode_audience",1)]

    with pytest.raises(ValidationError,match=r"authjwt_denylist_enabled"):
        @AuthJWT.load_config
        def get_invalid_denylist():
            return [("authjwt_denylist_enabled","test")]

    with pytest.raises(ValidationError,match=r"authjwt_denylist_token_checks"):
        @AuthJWT.load_config
        def get_invalid_denylist_token_checks():
            return [("authjwt_denylist_token_checks","string")]

    with pytest.raises(ValidationError,match=r"authjwt_denylist_token_checks"):
        @AuthJWT.load_config
        def get_invalid_denylist_str_token_check():
            return [("authjwt_denylist_token_checks",['access','refreshh'])]

    with pytest.raises(ValidationError,match=r"authjwt_header_name"):
        @AuthJWT.load_config
        def get_invalid_header_name():
            return [("authjwt_header_name",1)]

    with pytest.raises(ValidationError,match=r"authjwt_header_type"):
        @AuthJWT.load_config
        def get_invalid_header_type():
            return [("authjwt_header_type",1)]

    with pytest.raises(ValidationError,match=r"authjwt_access_token_expires"):
        @AuthJWT.load_config
        def get_invalid_access_token():
            return [("authjwt_access_token_expires","lol")]

    with pytest.raises(ValidationError,match=r"authjwt_access_token_expires"):
        @AuthJWT.load_config
        def get_access_token_true_value():
            return [("authjwt_access_token_expires",True)]

    with pytest.raises(ValidationError,match=r"authjwt_refresh_token_expires"):
        @AuthJWT.load_config
        def get_invalid_refresh_token():
            return [("authjwt_refresh_token_expires","lol")]

    with pytest.raises(ValidationError,match=r"authjwt_refresh_token_expires"):
        @AuthJWT.load_config
        def get_refresh_token_true_value():
            return [("authjwt_refresh_token_expires",True)]

    # option for create cookies
    with pytest.raises(ValidationError,match=r"authjwt_access_cookie_key"):
        @AuthJWT.load_config
        def get_invalid_access_cookie_key():
            return [("authjwt_access_cookie_key",1)]

    with pytest.raises(ValidationError,match=r"authjwt_refresh_cookie_key"):
        @AuthJWT.load_config
        def get_invalid_refresh_cookie_key():
            return [("authjwt_refresh_cookie_key",1)]

    with pytest.raises(ValidationError,match=r"authjwt_access_cookie_path"):
        @AuthJWT.load_config
        def get_invalid_access_cookie_path():
            return [("authjwt_access_cookie_path",1)]

    with pytest.raises(ValidationError,match=r"authjwt_refresh_cookie_path"):
        @AuthJWT.load_config
        def get_invalid_refresh_cookie_path():
            return [("authjwt_refresh_cookie_path",1)]

    with pytest.raises(ValidationError,match=r"authjwt_cookie_max_age"):
        @AuthJWT.load_config
        def get_invalid_cookie_max_age():
            return [("authjwt_cookie_max_age","string")]

    with pytest.raises(ValidationError,match=r"authjwt_cookie_domain"):
        @AuthJWT.load_config
        def get_invalid_cookie_domain():
            return [("authjwt_cookie_domain",1)]

    with pytest.raises(ValidationError,match=r"authjwt_cookie_secure"):
        @AuthJWT.load_config
        def get_invalid_cookie_secure():
            return [("authjwt_cookie_secure","string")]

    with pytest.raises(ValidationError,match=r"authjwt_cookie_samesite"):
        @AuthJWT.load_config
        def get_invalid_cookie_samesite_type():
            return [("authjwt_cookie_samesite",1)]

    with pytest.raises(ValidationError,match=r"authjwt_cookie_samesite"):
        @AuthJWT.load_config
        def get_invalid_cookie_samesite_value():
            return [("authjwt_cookie_samesite","laxx")]

    # option for double submit csrf protection
    with pytest.raises(ValidationError,match=r"authjwt_cookie_csrf_protect"):
        @AuthJWT.load_config
        def get_invalid_cookie_csrf_protect():
            return [("authjwt_cookie_csrf_protect",1)]

    with pytest.raises(ValidationError,match=r"authjwt_access_csrf_cookie_key"):
        @AuthJWT.load_config
        def get_invalid_access_csrf_cookie_key():
            return [("authjwt_access_csrf_cookie_key",1)]

    with pytest.raises(ValidationError,match=r"authjwt_refresh_csrf_cookie_key"):
        @AuthJWT.load_config
        def get_invalid_refresh_csrf_cookie_key():
            return [("authjwt_refresh_csrf_cookie_key",1)]

    with pytest.raises(ValidationError,match=r"authjwt_access_csrf_cookie_path"):
        @AuthJWT.load_config
        def get_invalid_access_csrf_cookie_path():
            return [("authjwt_access_csrf_cookie_path",1)]

    with pytest.raises(ValidationError,match=r"authjwt_refresh_csrf_cookie_path"):
        @AuthJWT.load_config
        def get_invalid_refresh_csrf_cookie_path():
            return [("authjwt_refresh_csrf_cookie_path",1)]

    with pytest.raises(ValidationError,match=r"authjwt_access_csrf_header_name"):
        @AuthJWT.load_config
        def get_invalid_access_csrf_header_name():
            return [("authjwt_access_csrf_header_name",1)]

    with pytest.raises(ValidationError,match=r"authjwt_refresh_csrf_header_name"):
        @AuthJWT.load_config
        def get_invalid_refresh_csrf_header_name():
            return [("authjwt_refresh_csrf_header_name",1)]

    with pytest.raises(ValidationError,match=r"authjwt_csrf_methods"):
        @AuthJWT.load_config
        def get_invalid_csrf_methods():
            return [("authjwt_csrf_methods",[1,2,3])]

    with pytest.raises(ValidationError,match=r"authjwt_csrf_methods"):
        @AuthJWT.load_config
        def get_invalid_csrf_methods_value():
            return [("authjwt_csrf_methods",['posts'])]
