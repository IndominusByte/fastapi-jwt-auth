from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from async_fastapi_jwt_auth import AuthJWT
from async_fastapi_jwt_auth.exceptions import AuthJWTException

"""
Note: This is just a basic example how to enable cookies.
This is vulnerable to CSRF attacks, and should not be used this example.
"""

app = FastAPI()


class User(BaseModel):
    username: str
    password: str


class Settings(BaseModel):
    authjwt_secret_key: str = "secret"
    # Configure application to store and get JWT from cookies
    authjwt_token_location: set = {"cookies"}
    # Disable CSRF Protection for this example. default is True
    authjwt_cookie_csrf_protect: bool = False


@AuthJWT.load_config
def get_config():
    return Settings()


@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


@app.post("/login")
async def login(user: User, Authorize: AuthJWT = Depends()):
    if user.username != "test" or user.password != "test":
        raise HTTPException(status_code=401, detail="Bad username or password")

    # Create the tokens and passing to set_access_cookies or set_refresh_cookies
    access_token = await Authorize.create_access_token(subject=user.username)
    refresh_token = await Authorize.create_refresh_token(subject=user.username)

    # Set the JWT cookies in the response
    await Authorize.set_access_cookies(access_token)
    await Authorize.set_refresh_cookies(refresh_token)
    return {"msg": "Successfully login"}


@app.post("/refresh")
async def refresh(Authorize: AuthJWT = Depends()):
    await Authorize.jwt_refresh_token_required()

    current_user = await Authorize.get_jwt_subject()
    new_access_token = await Authorize.create_access_token(subject=current_user)
    # Set the JWT cookies in the response
    await Authorize.set_access_cookies(new_access_token)
    return {"msg": "The token has been refresh"}


@app.delete("/logout")
async def logout(Authorize: AuthJWT = Depends()):
    """
    Because the JWT are stored in an httponly cookie now, we cannot
    log the user out by simply deleting the cookies in the frontend.
    We need the backend to send us a response to delete the cookies.
    """
    await Authorize.jwt_required()

    await Authorize.unset_jwt_cookies()
    return {"msg": "Successfully logout"}


@app.get("/protected")
async def protected(Authorize: AuthJWT = Depends()):
    """
    We do not need to make any changes to our protected endpoints. They
    will all still function the exact same as they do when sending the
    JWT in via a headers instead of a cookies
    """
    await Authorize.jwt_required()

    current_user = await Authorize.get_jwt_subject()
    return {"user": current_user}
