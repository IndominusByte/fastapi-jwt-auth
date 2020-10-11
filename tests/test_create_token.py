import pytest

def test_create_access_token(Authorize):
    with pytest.raises(TypeError,match=r"missing 1 required positional argument"):
        Authorize.create_access_token()

    with pytest.raises(TypeError,match=r"identity"):
        Authorize.create_access_token(identity=0.123)

    with pytest.raises(TypeError,match=r"fresh"):
        Authorize.create_access_token(identity="test",fresh="lol")

def test_create_refresh_token(Authorize):
    with pytest.raises(TypeError,match=r"missing 1 required positional argument"):
        Authorize.create_refresh_token()

    with pytest.raises(TypeError,match=r"identity"):
        Authorize.create_refresh_token(identity=0.123)
