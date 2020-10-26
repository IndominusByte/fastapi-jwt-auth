Create a file `basic.py`:

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

# in production you can use Settings management
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
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message}
    )

# provide a method to create access tokens. The create_access_token()
# function is used to actually generate the token to use authorization
# later in endpoint protected
@app.post('/login')
def login(user: User, Authorize: AuthJWT = Depends()):
    if user.username != "test" and user.password != "test":
        raise HTTPException(status_code=401,detail="Bad username or password")

    # subject identifier for who this token is for example id or username from database
    access_token = Authorize.create_access_token(subject=user.username)
    return {"access_token": access_token}

# protect endpoint with function jwt_required(), which requires
# a valid access token in the request headers to access.
@app.get('/user')
def user(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    current_user = Authorize.get_jwt_subject()
    return {"user": current_user}
```

Run the server with:

```bash
$ uvicorn basic:app --host 0.0.0.0

INFO:     Started server process [9859]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

To access a jwt_required protected url, all we have to do is send in the JWT with the request. By default, this is done with an authorization header that looks like:

```
Authorization: Bearer <access_token>
```

We can see this in action using <b>curl</b>:

```bash
$ curl http://localhost:8000/user

{"detail":"Missing Authorization Header"}

$ curl -H "Content-Type: application/json" -X POST \
  -d '{"username":"test","password":"test"}' http://localhost:8000/login

{"access_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNjAzNjkyMjYxLCJuYmYiOjE2MDM2OTIyNjEsImp0aSI6IjZiMjZkZTkwLThhMDYtNDEzMy04MzZiLWI5ODJkZmI3ZjNmZSIsImV4cCI6MTYwMzY5MzE2MSwidHlwZSI6ImFjY2VzcyIsImZyZXNoIjpmYWxzZX0.ro5JMHEVuGOq2YsENkZigSpqMf5cmmgPP8odZfxrzJA"}

$ export TOKEN=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNjAzNjkyMjYxLCJuYmYiOjE2MDM2OTIyNjEsImp0aSI6IjZiMjZkZTkwLThhMDYtNDEzMy04MzZiLWI5ODJkZmI3ZjNmZSIsImV4cCI6MTYwMzY5MzE2MSwidHlwZSI6ImFjY2VzcyIsImZyZXNoIjpmYWxzZX0.ro5JMHEVuGOq2YsENkZigSpqMf5cmmgPP8odZfxrzJA

$ curl -H "Authorization: Bearer $TOKEN" http://localhost:8000

{"user":"test"}
```
