In some cases you want to use one endpoint for both, protected and unprotected. in this situation you can use function <b>jwt_optional()</b>. this will allow the endpoint to be accessed regardless of if a JWT is sent in the request or not. if a JWT get tampering or expired an error will be returned instead of calling the endpoint.

```python
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
    if user.username != "test" and user.password != "test":
        raise HTTPException(status_code=401,detail="Bad username or password")

    access_token = Authorize.create_access_token(subject=user.username)
    return {"access_token": access_token}

@app.get('/partially-protected')
def partially_protected(Authorize: AuthJWT = Depends()):
    Authorize.jwt_optional()

    # If no jwt is sent in the request, get_jwt_subject() will return None
    current_user = Authorize.get_jwt_subject() or "anonymous"
    return {"user": current_user}
```
