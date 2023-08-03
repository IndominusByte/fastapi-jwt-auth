from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from async_fastapi_jwt_auth import AuthJWT
from async_fastapi_jwt_auth.exceptions import AuthJWTException

app = FastAPI()


class User(BaseModel):
    username: str
    password: str


# set denylist enabled to True
# you can set to check access or refresh token or even both of them
class Settings(BaseModel):
    authjwt_secret_key: str = "secret"
    authjwt_denylist_enabled: bool = True
    authjwt_denylist_token_checks: set = {"access", "refresh"}


@AuthJWT.load_config
def get_config():
    return Settings()


@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


# A storage engine to save revoked tokens. in production,
# you can use Redis for storage system
denylist = set()


# For this example, we are just checking if the tokens jti
# (unique identifier) is in the denylist set. This could
# be made more complex, for example storing the token in Redis
# with the value true if revoked and false if not revoked
@AuthJWT.token_in_denylist_loader
async def check_if_token_in_denylist(decrypted_token):
    jti = decrypted_token["jti"]
    return jti in denylist


@app.post("/login")
async def login(user: User, Authorize: AuthJWT = Depends()):
    if user.username != "test" or user.password != "test":
        raise HTTPException(status_code=401, detail="Bad username or password")

    access_token = await Authorize.create_access_token(subject=user.username)
    refresh_token = await Authorize.create_refresh_token(subject=user.username)
    return {"access_token": access_token, "refresh_token": refresh_token}


# Standard refresh endpoint. Token in denylist will not
# be able to access this endpoint
@app.post("/refresh")
async def refresh(Authorize: AuthJWT = Depends()):
    await Authorize.jwt_refresh_token_required()

    current_user = await Authorize.get_jwt_subject()
    new_access_token = await Authorize.create_access_token(subject=current_user)
    return {"access_token": new_access_token}


# Endpoint for revoking the current users access token
@app.delete("/access-revoke")
async def access_revoke(Authorize: AuthJWT = Depends()):
    await Authorize.jwt_required()

    jti = (await Authorize.get_raw_jwt())["jti"]
    denylist.add(jti)
    return {"detail": "Access token has been revoke"}


# Endpoint for revoking the current users refresh token
@app.delete("/refresh-revoke")
async def refresh_revoke(Authorize: AuthJWT = Depends()):
    await Authorize.jwt_refresh_token_required()

    jti = (await Authorize.get_raw_jwt())["jti"]
    denylist.add(jti)
    return {"detail": "Refresh token has been revoke"}


# A token in denylist will not be able to access this any more
@app.get("/protected")
async def protected(Authorize: AuthJWT = Depends()):
    await Authorize.jwt_required()

    current_user = await Authorize.get_jwt_subject()
    return {"user": current_user}
