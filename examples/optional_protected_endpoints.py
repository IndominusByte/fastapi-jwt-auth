from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, Field
from fastapi_jwt_auth import AuthJWT

# set secret key to environ variable with this command
# export AUTHJWT_SECRET_KEY=secretkey, in terminal linux, macOS, Windows Bash
# run app with this command uvicorn optional_protected_endpoints:app --host 0.0.0.0 --port 5000
# if you install python-dotenv run this command below
# uvicorn optional_protected_endpoints:app --host 0.0.0.0 --port 5000 --env-file .env

app = FastAPI()

class User(BaseModel):
    username: str = Field(...,min_length=1)
    password: str = Field(...,min_length=1)

@app.post('/login',status_code=200)
def login(user: User):
    if user.username != 'test' or user.password != 'test':
        raise HTTPException(status_code=401,detail='Bad username or password')

    access_token = AuthJWT.create_access_token(identity=user.username)
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
