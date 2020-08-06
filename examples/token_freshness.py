from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, Field
from fastapi_jwt_auth import AuthJWT

# set secret key to environ variable with this command
# export AUTHJWT_SECRET_KEY=secretkey, in terminal linux
# run app with this command uvicorn token_freshness:app --host 0.0.0.0 --port 5000
# if you install python-dotenv run this command below
# uvicorn token_freshness:app --host 0.0.0.0 --port 5000 --env-file .env

app = FastAPI()

class User(BaseModel):
    username: str = Field(...,min_length=1)
    password: str = Field(...,min_length=1)

# Standard login endpoint. Will return a fresh access token and
# a refresh token
@app.post('/login',status_code=200)
def login(user: User):
    if user.username != 'test' or user.password != 'test':
        raise HTTPException(status_code=401,detail='Bad username or password')

    # create_access_token supports an optional 'fresh' argument,
    # which marks the token as fresh or non-fresh accordingly.
    # As we just verified their username and password, we are
    # going to mark the token as fresh here.
    ret = {
        'access_token': AuthJWT.create_access_token(identity=user.username,fresh=True),
        'refresh_token': AuthJWT.create_refresh_token(identity=user.username)
    }

    return ret

# Refresh token endpoint. This will generate a new access token from
# the refresh token, but will mark that access token as non-fresh,
# as we do not actually verify a password in this endpoint.
@app.post('/refresh',status_code=200)
def refresh(Authorize: AuthJWT = Depends()):
    Authorize.jwt_refresh_token_required()

    current_user = Authorize.get_jwt_identity()
    ret = {
        'access_token': AuthJWT.create_access_token(identity=current_user,fresh=False)
    }

    return ret

# Any valid JWT can access this endpoint
@app.get('/protected',status_code=200)
def protected(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    current_user = Authorize.get_jwt_identity()
    return {"logged_in_as": current_user}

# Only fresh JWTs can access this endpoint
@app.get('/protected-fresh',status_code=200)
def protected_fresh(Authorize: AuthJWT = Depends()):
    Authorize.fresh_jwt_required()

    current_user = Authorize.get_jwt_identity()
    return {"fresh_logged_in_as": current_user}
