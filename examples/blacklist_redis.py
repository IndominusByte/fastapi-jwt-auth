from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, Field
from datetime import timedelta
from fastapi_jwt_auth import AuthJWT
from redis import Redis

# Enable blacklisting and set secret key with environment variable
# export AUTHJWT_BLACKLIST_ENABLED=true for enable blacklisting
# export AUTHJWT_SECRET_KEY=secretkey for secret key
# run app with this command uvicorn blacklist_redis:app --host 0.0.0.0 --port 5000
# if you install python-dotenv run this command below
# uvicorn blacklist_redis:app --host 0.0.0.0 --port 5000 --env-file .env

# Setup expired token in redis
ACCESS_EXPIRES = int(timedelta(minutes=15).total_seconds())
REFRESH_EXPIRES = int(timedelta(days=30).total_seconds())

# Setup our redis connection for storing the blacklisted tokens
redis_conn = Redis(host='localhost', port=6379, db=0, decode_responses=True)

# Create our function to check if a token has been blacklisted. In this simple
# case, we will just store the tokens jti (unique identifier) in redis.
# This function will return the revoked status of a token. If a token exists
# in this store and value is true, token has been revoked
@AuthJWT.token_in_blacklist_loader
def check_if_token_in_blacklist(*args,**kwargs):
    jti = kwargs['decrypted_token']['jti']
    entry = redis_conn.get(jti)
    return entry and entry == 'true'


app = FastAPI()

class User(BaseModel):
    username: str = Field(...,min_length=1)
    password: str = Field(...,min_length=1)

# Standard login endpoint
@app.post('/login',status_code=200)
def login(user: User):
    if user.username != 'test' or user.password != 'test':
        raise HTTPException(status_code=401,detail='Bad username or password')

    ret = {
        'access_token': AuthJWT.create_access_token(identity=user.username),
        'refresh_token': AuthJWT.create_refresh_token(identity=user.username)
    }

    return ret

# A blacklisted refresh tokens will not be able to access this endpoint
@app.post('/refresh',status_code=200)
def refresh(Authorize: AuthJWT = Depends()):
    Authorize.jwt_refresh_token_required()

    current_user = Authorize.get_jwt_identity()
    ret = {
        'access_token': AuthJWT.create_access_token(identity=current_user)
    }

    return ret

# Endpoint for revoking the current users access token
@app.delete('/access_revoke',status_code=200)
def access_revoke(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    # Store the tokens in redis with the value true for revoked.
    # We can also set an expires time on these tokens in redis,
    # so they will get automatically removed after they expire.
    jti = Authorize.get_raw_jwt()['jti']
    redis_conn.setex(jti,ACCESS_EXPIRES,'true')
    return {"msg": "Access token revoked"}

# Endpoint for revoking the current users refresh token
@app.delete('/refresh_revoke',status_code=200)
def refresh_revoke(Authorize: AuthJWT = Depends()):
    Authorize.jwt_refresh_token_required()

    # Store the tokens in redis with the value true for revoked.
    # We can also set an expires time on these tokens in redis,
    # so they will get automatically removed after they expire.
    jti = Authorize.get_raw_jwt()['jti']
    redis_conn.setex(jti,REFRESH_EXPIRES,'true')
    return {"msg": "Refresh token revoked"}

# A blacklisted access token will not be able to access this any more
@app.get('/protected',status_code=200)
def protected(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    current_user = Authorize.get_jwt_identity()
    return {"logged_in_as": current_user}
