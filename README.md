# fastapi-jwt-auth

[![Build Status](https://travis-ci.org/IndominusByte/fastapi-jwt-auth.svg?branch=master)](https://travis-ci.org/IndominusByte/fastapi-jwt-auth)
[![Coverage Status](https://coveralls.io/repos/github/IndominusByte/fastapi-jwt-auth/badge.svg?branch=master)](https://coveralls.io/github/IndominusByte/fastapi-jwt-auth?branch=master)
[![PyPI version](https://badge.fury.io/py/fastapi-jwt-auth.svg)](https://badge.fury.io/py/fastapi-jwt-auth)
[![Downloads](https://pepy.tech/badge/fastapi-jwt-auth/month)](https://pepy.tech/project/fastapi-jwt-auth/month)
[![Downloads](https://pepy.tech/badge/fastapi-jwt-auth)](https://pepy.tech/project/fastapi-jwt-auth)

## Features
FastAPI extension that provides JWT Auth support (secure, easy to use and lightweight), if you were familiar with flask-jwt-extended this extension suitable for you because this extension inspired by flask-jwt-extended.
- Access token and refresh token
- Token freshness will only allow fresh tokens to access endpoint
- Token revoking/blacklisting
- Custom token revoking

## Installation
```bash
pip install fastapi-jwt-auth
```

## Usage
### Setting `AUTHJWT_SECRET_KEY` in environment variable
- For Linux, macOS, Windows Bash
```bash
export AUTHJWT_SECRET_KEY=secretkey
```
- For Windows PowerShell
```bash
$Env:AUTHJWT_SECRET_KEY = "secretkey"
```
### Create it
- Create a file `basic.py` with:
```python
from fastapi import FastAPI, Depends, HTTPException
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseModel, Field

app = FastAPI()

class User(BaseModel):
    username: str = Field(...,min_length=1)
    password: str = Field(...,min_length=1)

# Provide a method to create access tokens. The create_access_token()
# function is used to actually generate the token, and you can return
# it to the caller however you choose.
@app.post('/login',status_code=200)
def login(user: User, Authorize: AuthJWT = Depends()):
    if user.username != 'test' or user.password != 'test':
        raise HTTPException(status_code=401,detail='Bad username or password')

    # identity must be between string or integer
    access_token = Authorize.create_access_token(identity=user.username)
    return {"access_token": access_token}

@app.get('/protected',status_code=200)
def protected(Authorize: AuthJWT = Depends()):
    # Protect an endpoint with jwt_required, which requires a valid access token
    # in the request to access.
    Authorize.jwt_required()

    # Access the identity of the current user with get_jwt_identity
    current_user = Authorize.get_jwt_identity()
    return {"logged_in_as": current_user}

```
### Run it
Run the server with:
```console
$ uvicorn basic:app --host 0.0.0.0

INFO:     Started server process [4235]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```
### Access it
To access a jwt_required protected url, all we have to do is send in the JWT with the request. By default, this is done with an authorization header that looks like:
```bash
Authorization: Bearer <access_token>
```
We can see this in action using CURL:
```console
$ curl http://localhost:8000/protected

{"detail":"Missing Authorization Header"}

$ curl -H "Content-Type: application/json" -X POST \
  -d '{"username":"test","password":"test"}' http://localhost:8000/login
 
"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1OTczMzMxMzMsIm5iZiI6MTU5NzMzMzEzMywianRpIjoiNDczY2ExM2ItOWI1My00NDczLWJjZTctMWZiOWMzNTlmZmI0IiwiZXhwIjoxNTk3MzM0MDMzLCJpZGVudGl0eSI6InRlc3QiLCJ0eXBlIjoiYWNjZXNzIiwiZnJlc2giOmZhbHNlfQ.42CusQo6nsLxOk6bBUP1vnVX-REx4ZYBYYIjYChWf0c"

$ export TOKEN=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1OTczMzMxMzMsIm5iZiI6MTU5NzMzMzEzMywianRpIjoiNDczY2ExM2ItOWI1My00NDczLWJjZTctMWZiOWMzNTlmZmI0IiwiZXhwIjoxNTk3MzM0MDMzLCJpZGVudGl0eSI6InRlc3QiLCJ0eXBlIjoiYWNjZXNzIiwiZnJlc2giOmZhbHNlfQ.42CusQo6nsLxOk6bBUP1vnVX-REx4ZYBYYIjYChWf0c

$ curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/protected

{"logged_in_as":"test"}
```
## Extract Token
Access all URL to see what the result
```python
from fastapi import FastAPI, Depends, HTTPException
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseModel, Field

app = FastAPI()

class User(BaseModel):
    username: str = Field(...,min_length=1)
    password: str = Field(...,min_length=1)

@app.post('/login',status_code=200)
def login(user: User, Authorize: AuthJWT = Depends()):
    if user.username != 'test' or user.password != 'test':
        raise HTTPException(status_code=401,detail='Bad username or password')

    access_token = Authorize.create_access_token(identity=user.username)
    return access_token

# Returns the JTI (unique identifier) of an encoded JWT
@app.get('/get-jti',status_code=200)
def get_jti(Authorize: AuthJWT = Depends()):
    access_token = Authorize.create_access_token(identity='test')
    return Authorize.get_jti(encoded_token=access_token)

# this will return the identity of the JWT that is accessing this endpoint.
# If no JWT is present, `None` is returned instead.
@app.get('/get-jwt-identity',status_code=200)
def get_jwt_identity(Authorize: AuthJWT = Depends()):
    Authorize.jwt_optional()

    current_user = Authorize.get_jwt_identity()
    return {"logged_in_as": current_user}

# this will return the python dictionary which has all
# of the claims of the JWT that is accessing the endpoint.
# If no JWT is currently present, return None instead
@app.get('/get-raw-jwt',status_code=200)
def get_raw_jwt(Authorize: AuthJWT = Depends()):
    Authorize.jwt_optional()

    token = Authorize.get_raw_jwt()
    return {"token": token}
```

## Configuration Options (env)
- `AUTHJWT_ACCESS_TOKEN_EXPIRES`<br/>
How long an access token should live before it expires. If you not define in env variable
default value is `15 minutes`. Or you can custom with value `int` (seconds), example
`AUTHJWT_ACCESS_TOKEN_EXPIRES=300` its mean access token expired in 5 minute

- `AUTHJWT_REFRESH_TOKEN_EXPIRES`<br/>
How long a refresh token should live before it expires. If you not define in env variable
default value is `30 days`. Or you can custom with value `int` (seconds), example
`AUTHJWT_REFRESH_TOKEN_EXPIRES=86400` its mean refresh token expired in 1 day

- `AUTHJWT_BLACKLIST_ENABLED`<br/>
Enable/disable token revoking. Default value is None, for enable blacklist token: `AUTHJWT_BLACKLIST_ENABLED=true`

- `AUTHJWT_SECRET_KEY`<br/>
The secret key needed for symmetric based signing algorithms, such as HS*. If this is not set `raise RuntimeError`.

- `AUTHJWT_ALGORITHM`<br/>
Which algorithms are allowed to decode a JWT. Default value is `HS256`

## Configuration (pydantic or list[tuple])
You can convert and validate type data from dotenv through pydantic (BaseSettings)
```python
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseSettings
from datetime import timedelta
from typing import Literal

# dotenv file parsing requires python-dotenv to be installed
# This can be done with either pip install python-dotenv
class Settings(BaseSettings):
    authjwt_access_token_expires: timedelta = timedelta(minutes=15)
    authjwt_refresh_token_expires: timedelta = timedelta(days=30)
    # literal type only available for python 3.8
    authjwt_blacklist_enabled: Literal['true','false']
    authjwt_secret_key: str
    authjwt_algorithm: str = 'HS256'

    class Config:
        env_file = '.env'
        env_file_encoding = 'utf-8'


@AuthJWT.load_env
def get_settings():
    return Settings()
    # or you can just parse a list of tuple
    # return [
    #     ("authjwt_access_token_expires",timedelta(minutes=2)),
    #     ("authjwt_refresh_token_expires",timedelta(days=5)),
    #     ("authjwt_blacklist_enabled","false"),
    #     ("authjwt_secret_key","testing"),
    #     ("authjwt_algorithm","HS256")
    # ]


print(AuthJWT._access_token_expires)
print(AuthJWT._refresh_token_expires)
print(AuthJWT._blacklist_enabled)
print(AuthJWT._secret_key)
print(AuthJWT._algorithm)
```

## Examples
Examples are available on [examples](/examples) folder.
There are:
- [Basic](/examples/basic.py)
- [Token Optional](/examples/optional_protected_endpoints.py)
- [Refresh Token](/examples/refresh_tokens.py)
- [Token Fresh](/examples/token_freshness.py)
- [Blacklist Token](/examples/blacklist.py)
- [Blacklist Token Use Redis](/examples/blacklist_redis.py)

Optional:
- [Use AuthJWT Without Dependency Injection](/examples/without_dependency.py)
- [On Mutiple Files](/examples/multiple_files)

## License
This project is licensed under the terms of the MIT license.
