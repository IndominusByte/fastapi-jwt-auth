from fastapi import FastAPI, Depends, HTTPException
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseModel, Field

app = FastAPI()

class User(BaseModel):
    username: str = Field(...,min_length=1)
    password: str = Field(...,min_length=1)


"""
you can use AuthJWT without dependency injection, in some cases you only need to
create a token without validating an incoming token.
"""
class JwtAuthToken:
    def __init__(self):
        self.jwt_auth = AuthJWT(None)

    def __call__(self):
        return self.jwt_auth


auth_token = JwtAuthToken()

@app.post('/login',status_code=200)
def login(user: User, Authorize: AuthJWT = Depends(auth_token)):
    if user.username != 'test' or user.password != 'test':
        raise HTTPException(status_code=401,detail='Bad username or password')

    access_token = Authorize.create_access_token(identity=user.username)
    return {"access_token": access_token}

@app.get('/protected',status_code=200)
def protected(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    current_user = Authorize.get_jwt_identity()
    return {"logged_in_as": current_user}
