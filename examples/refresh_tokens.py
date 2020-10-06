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

    # Use create_access_token() and create_refresh_token() to create our
    # access and refresh tokens
    ret = {
        'access_token': Authorize.create_access_token(identity=user.username),
        'refresh_token': Authorize.create_refresh_token(identity=user.username)
    }

    return ret


"""
The jwt_refresh_token_required function insures a valid refresh
token is present in the request before calling this endpoint. We
can use the get_jwt_identity() function to get the identity of
the refresh token, and use the create_access_token() function again
to make a new access token for this identity.
The jwt_refresh_token_required function insures a valid refresh
"""
@app.post('/refresh',status_code=200)
def refresh(Authorize: AuthJWT = Depends()):
    Authorize.jwt_refresh_token_required()

    current_user = Authorize.get_jwt_identity()
    return {'access_token': Authorize.create_access_token(identity=current_user)}

@app.get('/protected',status_code=200)
def protected(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    current_user = Authorize.get_jwt_identity()
    return {"logged_in_as": current_user}
