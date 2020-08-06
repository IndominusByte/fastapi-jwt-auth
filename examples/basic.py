from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, Field
from fastapi_jwt_auth import AuthJWT

# set secret key to environ variable with this command
# export AUTHJWT_SECRET_KEY=secretkey, in terminal linux
# run app with this command uvicorn basic:app --host 0.0.0.0 --port 5000
# if you install python-dotenv run this command below
# uvicorn basic:app --host 0.0.0.0 --port 5000 --env-file .env

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
