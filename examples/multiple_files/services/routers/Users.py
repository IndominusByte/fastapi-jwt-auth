from fastapi_jwt_auth import AuthJWT
from fastapi import APIRouter, Response, Depends
from controller.UserController import UserCrud, UserFetch, UserLogic
from schemas.users.RegisterSchema import RegisterSchema
from schemas.users.UserSchema import UserLogin, UserOut, UserUpdate
from config import conn_redis, ACCESS_EXPIRES, REFRESH_EXPIRES
from typing import List

class JwtAuthToken:
    def __init__(self):
        self.jwt_auth = AuthJWT(None)

    def __call__(self):
        return self.jwt_auth


router = APIRouter()
auth_token = JwtAuthToken()

@router.post('/register', status_code=201)
async def register(user: RegisterSchema):
    await UserCrud.create_user(**user.dict(exclude={'confirm_password'}))
    return {"message":"email already register"}

@router.post('/login')
async def login(user: UserLogin, res: Response, Authorize: AuthJWT = Depends(auth_token)):
    user_exists = await UserFetch.filter_by_email(user.email)
    if (
        user_exists and
        UserLogic.check_user_password(password=user.password,hashed_pass=user_exists.password)
    ):
        access_token = Authorize.create_access_token(identity=user_exists.id,fresh=True)
        refresh_token = Authorize.create_refresh_token(identity=user_exists.id)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "username": user_exists.username
        }

    res.status_code = 422
    return {"message":"Invalid credential"}

@router.post('/refresh-token')
async def refresh_token(Authorize: AuthJWT = Depends()):
    Authorize.jwt_refresh_token_required()

    user_id = Authorize.get_jwt_identity()
    new_token = Authorize.create_access_token(identity=user_id,fresh=False)
    return {"access_token": new_token}

@router.delete('/access-token-revoke')
async def access_token_revoke(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    jti = Authorize.get_raw_jwt()['jti']
    conn_redis.setex(jti,ACCESS_EXPIRES,"true")
    return {"message":"Access token revoked."}

@router.delete('/refresh-token-revoke')
async def refresh_token_revoke(Authorize: AuthJWT = Depends()):
    Authorize.jwt_refresh_token_required()

    jti = Authorize.get_raw_jwt()['jti']
    conn_redis.setex(jti,REFRESH_EXPIRES,"true")
    return {"message":"Refresh token revoked."}

@router.get('/me', response_model=UserOut)
async def get_my_user(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    user_id = Authorize.get_jwt_identity()
    return await UserFetch.filter_by_id(id=user_id)

@router.get('/', response_model=List[UserOut])
async def all_user():
    return await UserFetch.all_user()

@router.put('/update')
async def update_user(user: UserUpdate, Authorize: AuthJWT = Depends()):
    Authorize.fresh_jwt_required()

    user_id = Authorize.get_jwt_identity()
    await UserCrud.update_user(user_id=user_id,**user.dict())
    return {"message": "Success update your account."}

@router.delete('/{user_id}')
async def delete_user(user_id: int):
    await UserCrud.delete_user(user_id=user_id)
    return {"message": "Success delete user."}
