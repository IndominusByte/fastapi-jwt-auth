# fastapi-jwt-auth

[![Build Status](https://travis-ci.org/IndominusByte/fastapi-jwt-auth.svg?branch=master)](https://travis-ci.org/IndominusByte/fastapi-jwt-auth)
[![Coverage Status](https://coveralls.io/repos/github/IndominusByte/fastapi-jwt-auth/badge.svg?branch=master)](https://coveralls.io/github/IndominusByte/fastapi-jwt-auth?branch=master)
[![PyPI version](https://badge.fury.io/py/fastapi-jwt-auth.svg)](https://badge.fury.io/py/fastapi-jwt-auth)
![GitHub](https://img.shields.io/github/license/IndominusByte/fastapi-jwt-auth)

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
from pydantic import BaseModel, Field
from fastapi_jwt_auth import AuthJWT

app = FastAPI()

class User(BaseModel):
    username: str = Field(...,min_length=1)
    password: str = Field(...,min_length=1)

# Provide a method to create access tokens. The create_access_token()
# function is used to actually generate the token, and you can return
# it to the caller however you choose.
@app.post('/login',status_code=200)
def login(user: User):
    if user.username != 'test' or user.password != 'test':
        raise HTTPException(status_code=401,detail='Bad username or password')

    # Identity can be any data that is json serializable
    access_token = AuthJWT.create_access_token(identity=user.username)
    return access_token

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
$ uvicorn basic:app --host 0.0.0.0 --port 5000

INFO:     Started server process [6051]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:5000 (Press CTRL+C to quit)
```
## Configuration Options
- AUTHJWT_ACCESS_TOKEN_EXPIRES<br/>
How long an access token should live before it expires. If you not define in env variable
default value is `15 minutes`. Or you can custom with value `int` (seconds), example
`AUTHJWT_ACCESS_TOKEN_EXPIRES=300` its mean access token expired in 5 minute

- AUTHJWT_REFRESH_TOKEN_EXPIRES<br/>
How long a refresh token should live before it expires. If you not define in env variable
default value is `30 days`. Or you can custom with value `int` (seconds), example
`AUTHJWT_REFRESH_TOKEN_EXPIRES=86400` its mean refresh token expired in 1 day

- AUTHJWT_BLACKLIST_ENABLED<br/>
Enable/disable token revoking. Default value is None, for enable blacklist token: `AUTHJWT_BLACKLIST_ENABLED=true`

- AUTHJWT_SECRET_KEY<br/>
The secret key needed for symmetric based signing algorithms, such as HS*. If this is not set `raise RuntimeError`.

- AUTHJWT_ALGORITHM<br/>
Which algorithms are allowed to decode a JWT. Default value is `HS256`

## Examples
Examples are available on [examples](/examples) folder.
There are:
- [Basic](/examples/basic.py)
- [Blacklist Token](/examples/blacklist.py)
- [Blacklist Token Use Redis](/examples/blacklist_redis.py)
- [Token Optional](/examples/optional_protected_endpoints.py)
- [Refresh Token](/examples/refresh_tokens.py)
- [Token Fresh](/examples/token_freshness.py)

## License
This project is licensed under the terms of the MIT license.
