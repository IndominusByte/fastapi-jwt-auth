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

@app.get('/partially-protected',status_code=200)
def protected(Authorize: AuthJWT = Depends()):
    Authorize.jwt_optional()

    # If no JWT is sent in with the request, get_jwt_identity()
    # will return None
    current_user = Authorize.get_jwt_identity()
    if current_user:
        return {"logged_in_as": current_user}
    else:
        return {"logged_in_as": "anonymous user"}
