from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from pydantic import BaseModel

app = FastAPI()

class User(BaseModel):
    username: str
    password: str

class Settings(BaseModel):
    authjwt_secret_key: str = "secret"

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

    # You can be passing custom claim to argument user_claims
    # in function create_access_token() or create refresh token()
    another_claims = {"foo": ["fiz","baz"]}
    access_token = Authorize.create_access_token(subject=user.username,user_claims=another_claims)
    return {"access_token": access_token}

# In protected route, get the claims you added to the jwt with the
# get_raw_jwt() method
@app.get('/claims')
def user(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    foo_claims = Authorize.get_raw_jwt()['foo']
    return {"foo": foo_claims}
