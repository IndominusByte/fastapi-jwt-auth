import uvicorn, socket
from fastapi import FastAPI, Depends
from fastapi_jwt_auth.JWTAuthorization import AuthJWT

# ignore this function
def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]


app = FastAPI(debug=True)

# ========= MAKE JWT SYSTEM EXAMPLE =========
@app.get('/jwt-create')
def test_jwt():
    access_token = AuthJWT.create_access_token(identity=5,type_token="access",fresh=True)
    refresh_token = AuthJWT.create_refresh_token(identity=5,type_token="refresh")
    # print(AuthJWT.get_jti(encoded_token=access_token))
    return {"access_token": access_token, "refresh_token": refresh_token}

@app.get('/jwt-required')
def check_jwt_required(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    # print(Authorize.get_raw_jwt())
    # print(Authorize.get_jwt_identity())

@app.get('/jwt-optional')
def check_jwt_optional(Authorize: AuthJWT = Depends()):
    Authorize.jwt_optional()

@app.get('/jwt-refresh-required')
def check_jwt_refresh_required(Authorize: AuthJWT = Depends()):
    Authorize.jwt_refresh_token_required()

@app.get('/jwt-fresh-required')
def check_jwt_fresh(Authorize: AuthJWT = Depends()):
    Authorize.fresh_jwt_required()

@app.get('/jwt-logout')
def jwt_logout(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    jti = Authorize.get_raw_jwt()['jti']
    Authorize.revoke_access_token(jti)
    # Authorize.revoke_refresh_token(jti)

@app.get('/refresh-token')
def refresh_token(Authorize: AuthJWT = Depends()):
    Authorize.jwt_refresh_token_required()
    access_token = Authorize.create_access_token(identity=5,type_token="access",fresh=False)
    return {"access_token": access_token}


if __name__ == '__main__':
    uvicorn.run("example:app",host=get_ip_address(),port=5000,reload=True)
