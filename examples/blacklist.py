from fastapi import FastAPI, Depends, HTTPException
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseModel, Field

"""
Enable blacklisting and set secret key with environment variable
export AUTHJWT_BLACKLIST_ENABLED=true for enable blacklisting
export AUTHJWT_SECRET_KEY=secretkey for secret key
run app with this command uvicorn blacklist:app --host 0.0.0.0
"""

# A storage engine to save revoked tokens. in production,
# you can use Redis for storage system
blacklist = set()

# For this example, we are just checking if the tokens jti
# (unique identifier) is in the blacklist set. This could
# be made more complex, for example storing the token in Redis
# with the value true if revoked and false if not revoked
@AuthJWT.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist


app = FastAPI()

class User(BaseModel):
    username: str = Field(...,min_length=1)
    password: str = Field(...,min_length=1)

# Standard login endpoint
@app.post('/login',status_code=200)
def login(user: User, Authorize: AuthJWT = Depends()):
    if user.username != 'test' or user.password != 'test':
        raise HTTPException(status_code=401,detail='Bad username or password')

    ret = {
        'access_token': Authorize.create_access_token(identity=user.username),
        'refresh_token': Authorize.create_refresh_token(identity=user.username)
    }

    return ret

# A blacklisted access token will not be able to access this any more
@app.get('/protected',status_code=200)
def protected(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    current_user = Authorize.get_jwt_identity()
    return {"logged_in_as": current_user}

# A blacklisted refresh tokens will not be able to access this endpoint
@app.post('/refresh',status_code=200)
def refresh(Authorize: AuthJWT = Depends()):
    Authorize.jwt_refresh_token_required()

    current_user = Authorize.get_jwt_identity()
    return {'access_token': Authorize.create_access_token(identity=current_user)}

# Endpoint for revoking the current users access token
@app.delete('/access_revoke',status_code=200)
def access_revoke(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    jti = Authorize.get_raw_jwt()['jti']
    blacklist.add(jti)
    return {"msg": "Access token revoked"}

# Endpoint for revoking the current users refresh token
@app.delete('/refresh_revoke',status_code=200)
def refresh_revoke(Authorize: AuthJWT = Depends()):
    Authorize.jwt_refresh_token_required()

    jti = Authorize.get_raw_jwt()['jti']
    blacklist.add(jti)
    return {"msg": "Refresh token revoked"}
