from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from pydantic import BaseModel

# In the real case, you can put the
# public key and private key in *.txt then you can read that file
private_key = """
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgGBoQhqHdMU65aSBQVC/u9a6HMfKA927aZOk7HA/kXuA5UU4Sl+U
C9WjDhMQFk1PpqAjZdCqx9ajolTYnIfeaVHcLNpJQ6QXLnUyMnfwPmwYQ2rkuy5w
I2NdO81CzJ/9S8MsPyMl2/CF9ZxM03eleE8RKFwXCxZ/IoiqN4jVNjSrAgMBAAEC
gYAnNqEUq146zx8TT6PilWpxB9inByuVaCKkdGPbsG+bfa1D/4Z44/4AUsdpx5Ra
s/hBkMRcIOsSChMAUe8xcK0DqA9Y7BIVfpma2fH/gYq6dP3dOfCxftZBF00HwIu7
5e7RWnBC8MkPnrkKdHq6ptAYlGgoSJTEQREqusDiuNG9yQJBAKQib2VhNAqgyvvi
PdmFrCqq15z9MY16WCfttuqfAaSYKHnZe1WvBKbSNW9x4Cgjfhzl9mlozlW4rob/
ttPN6e0CQQCWXbVtqmVdB5Ol9wQN7DIRc8q5F8HKQqIJAMTmwaRwNDsGRxCWMwGO
8WAlnejzYTXmrrytv6kXX8U40enJW2X3AkAI42h+5/WmgbCcVVMeHXQGV3wXn0p4
q+BsQR4/tF6laCwA9TsNl827rvR/1X3bDpj8vaNLcAaEc9zXqK9g5uy9AkATeOkw
3Xso8/075eRBhU/qkKs1Ew2GiuB+9/mHxJXt7eWi53sPaGWQRFPmKy/qrLEVQZWv
jn1wSHe65vw2lj57AkEAh04n1wrZnCha8s6crMhjggdTXI6G4FU3TGf8ssGboqs3
j5lemvyKod+u2JVKwarcKmd/gFYBOjsRm18LlZH74A==
-----END RSA PRIVATE KEY-----
"""
public_key = """
-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgGBoQhqHdMU65aSBQVC/u9a6HMfK
A927aZOk7HA/kXuA5UU4Sl+UC9WjDhMQFk1PpqAjZdCqx9ajolTYnIfeaVHcLNpJ
Q6QXLnUyMnfwPmwYQ2rkuy5wI2NdO81CzJ/9S8MsPyMl2/CF9ZxM03eleE8RKFwX
CxZ/IoiqN4jVNjSrAgMBAAE=
-----END PUBLIC KEY-----
"""

app = FastAPI()

class User(BaseModel):
    username: str
    password: str

class Settings(BaseModel):
    authjwt_algorithm: str = "RS512"
    authjwt_public_key: str = public_key
    authjwt_private_key: str = private_key

@AuthJWT.load_config
def get_config():
    return Settings()

@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message}
    )

@app.post('/login')
def login(user: User, Authorize: AuthJWT = Depends()):
    if user.username != "test" or user.password != "test":
        raise HTTPException(status_code=401,detail="Bad username or password")

    access_token = Authorize.create_access_token(subject=user.username)
    refresh_token = Authorize.create_refresh_token(subject=user.username)
    return {"access_token": access_token, "refresh_token": refresh_token}

@app.post('/refresh')
def refresh(Authorize: AuthJWT = Depends()):
    Authorize.jwt_refresh_token_required()

    current_user = Authorize.get_jwt_subject()
    new_access_token = Authorize.create_access_token(subject=current_user)
    return {"access_token": new_access_token}

@app.get('/protected')
def protected(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    current_user = Authorize.get_jwt_subject()
    return {"user": current_user}
