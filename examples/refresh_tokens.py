import uvicorn
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, Field
from fastapi_jwt_auth import AuthJWT

app = FastAPI()

class User(BaseModel):
    username: str = Field(...,min_length=1)
    password: str = Field(...,min_length=1)

@app.post('/login',status_code=200)
def login(user: User):
    if user.username != 'test' or user.password != 'test':
        raise HTTPException(status_code=401,detail='Bad username or password')

    # Use create_access_token() and create_refresh_token() to create our
    # access and refresh tokens
    ret = {
        'access_token': AuthJWT.create_access_token(identity=user.username),
        'refresh_token': AuthJWT.create_refresh_token(identity=user.username)
    }

    return ret

# The jwt_refresh_token_required function insures a valid refresh
# token is present in the request before calling this endpoint. We
# can use the get_jwt_identity() function to get the identity of
# the refresh token, and use the create_access_token() function again
# to make a new access token for this identity.
@app.post('/refresh',status_code=200)
def refresh(Authorize: AuthJWT = Depends()):
    Authorize.jwt_refresh_token_required()

    current_user = Authorize.get_jwt_identity()
    ret = {
        'access_token': AuthJWT.create_access_token(identity=current_user)
    }

    return ret

@app.get('/protected',status_code=200)
def protected(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    current_user = Authorize.get_jwt_identity()
    return {"logged_in_as": current_user}


if __name__ == '__main__':
    uvicorn.run("refresh_tokens:app",host='0.0.0.0',port=5000,reload=True)
