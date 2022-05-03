import jwt
import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseSettings

from fastapi_jwt_auth import AuthJWT


@pytest.fixture(scope="function")
def client() -> TestClient:
    app = FastAPI()

    @app.get("/protected")
    def protected(Authorize: AuthJWT = Depends()):
        Authorize.jwt_required()
        return {"hello": "world"}

    @app.get("/semi_protected")
    def protected(Authorize: AuthJWT = Depends()):
        Authorize.jwt_optional()
        return {"hello": "world"}

    @app.get("/refresh")
    def refresher(Authorize: AuthJWT = Depends()):
        Authorize.jwt_refresh_token_required()
        return {"hello": "world"}

    client = TestClient(app)
    return client


def test_custom_token_type_claim_validation(
    client: TestClient, Authorize: AuthJWT
) -> None:
    class TestConfig(BaseSettings):
        authjwt_secret_key: str = "secret"
        authjwt_token_type_claim_name: str = "custom_type"

    @AuthJWT.load_config
    def test_config():
        return TestConfig()

    # Checking that created token has custom type claim
    access = Authorize.create_access_token(subject="test")
    assert (
        jwt.decode(access, key="secret", algorithms=["HS256"])["custom_type"]
        == "access"
    )

    # Checking that protected endpoint validates token correctly
    response = client.get("/protected", headers={"Authorization": f"Bearer {access}"})
    assert response.status_code == 200
    assert response.json() == {"hello": "world"}

    # Checking that endpoint with optional protection validates token with
    # custom type claim correctly.
    response = client.get(
        "/semi_protected", headers={"Authorization": f"Bearer {access}"}
    )
    assert response.status_code == 200
    assert response.json() == {"hello": "world"}

    # Creating refresh token and checking if it has correct
    # type claim.
    refresh = Authorize.create_refresh_token(subject="test")
    assert (
        jwt.decode(refresh, key="secret", algorithms=["HS256"])["custom_type"]
        == "refresh"
    )

    # Checking that refreshing with custom claim works.
    response = client.get("/refresh", headers={"Authorization": f"Bearer {refresh}"})
    assert response.status_code == 200
    assert response.json() == {"hello": "world"}


def test_custom_token_type_names_validation(
    client: TestClient, Authorize: AuthJWT
) -> None:
    class TestConfig(BaseSettings):
        authjwt_secret_key: str = "secret"
        authjwt_refresh_token_type: str = "refresh_custom"
        authjwt_access_token_type: str = "access_custom"

    @AuthJWT.load_config
    def test_config():
        return TestConfig()

    # Creating access token and checking that
    # it has custom type
    access = Authorize.create_access_token(subject="test")
    assert (
        jwt.decode(access, key="secret", algorithms=["HS256"])["type"]
        == "access_custom"
    )

    # Checking that validation for custom type works as expected.
    response = client.get("/protected", headers={"Authorization": f"Bearer {access}"})
    assert response.status_code == 200
    assert response.json() == {"hello": "world"}

    response = client.get(
        "/semi_protected", headers={"Authorization": f"Bearer {access}"}
    )
    assert response.status_code == 200
    assert response.json() == {"hello": "world"}

    # Creating refresh token and checking if it has correct type claim.
    refresh = Authorize.create_refresh_token(subject="test")
    assert (
        jwt.decode(refresh, key="secret", algorithms=["HS256"])["type"]
        == "refresh_custom"
    )

    # Checking that refreshing with custom type works.
    response = client.get("/refresh", headers={"Authorization": f"Bearer {refresh}"})
    assert response.status_code == 200
    assert response.json() == {"hello": "world"}


def test_without_type_claims(client: TestClient, Authorize: AuthJWT) -> None:
    class TestConfig(BaseSettings):
        authjwt_secret_key: str = "secret"
        authjwt_token_type_claim: bool = False

    @AuthJWT.load_config
    def test_config():
        return TestConfig()

    # Creating access token and checking if it doesn't have type claim.
    access = Authorize.create_access_token(subject="test")
    assert "type" not in jwt.decode(access, key="secret", algorithms=["HS256"])

    response = client.get("/protected", headers={"Authorization": f"Bearer {access}"})
    assert response.status_code == 200
    assert response.json() == {"hello": "world"}

    response = client.get(
        "/semi_protected", headers={"Authorization": f"Bearer {access}"}
    )
    assert response.status_code == 200
    assert response.json() == {"hello": "world"}

    # Creating refresh token and checking if it doesn't have type claim.
    refresh = Authorize.create_refresh_token(subject="test")
    assert "type" not in jwt.decode(refresh, key="secret", algorithms=["HS256"])

    # Checking that refreshing without type works.
    response = client.get("/refresh", headers={"Authorization": f"Bearer {refresh}"})
    assert response.status_code == 200
    assert response.json() == {"hello": "world"}
