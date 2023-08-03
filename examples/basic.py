from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from async_fastapi_jwt_auth import AuthJWT
from async_fastapi_jwt_auth.exceptions import AuthJWTException

app = FastAPI()


class User(BaseModel):
    username: str
    password: str


# in production, you can use Settings management
# from pydantic to get secret key from .env
class Settings(BaseModel):
    authjwt_secret_key: str = "secret"


# callback to get your configuration
@AuthJWT.load_config
def get_config():
    return Settings()


# exception handler for authjwt
# in production, you can tweak performance using orjson response
@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


# provide a method to create access tokens. The create_access_token()
# function is used to actually generate the token to use authorization
# later in endpoint protected
@app.post("/login")
async def login(user: User, Authorize: AuthJWT = Depends()):
    if user.username != "test" or user.password != "test":
        raise HTTPException(status_code=401, detail="Bad username or password")

    # subject identifier for whom this token is for example id or username from database
    access_token = await Authorize.create_access_token(subject=user.username)
    return {"access_token": access_token}


# protect endpoint with function jwt_required(), which requires
# a valid access token in the request headers to access.
@app.get("/user")
async def user(Authorize: AuthJWT = Depends()):
    await Authorize.jwt_required()

    current_user = await Authorize.get_jwt_subject()
    return {"user": current_user}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("basic:app", host="0.0.0.0", port=8000, reload=True)
