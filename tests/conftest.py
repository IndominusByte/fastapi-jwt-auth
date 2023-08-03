import pytest

from async_fastapi_jwt_auth import AuthJWT


@pytest.fixture(scope="module")
def Authorize():
    return AuthJWT()
