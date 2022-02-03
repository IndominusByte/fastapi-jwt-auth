from fastapi import APIRouter, Depends, HTTPException
from async_fastapi_jwt_auth import AuthJWT
from pydantic import BaseModel


class User(BaseModel):
    username: str
    password: str


router = APIRouter()


@router.post('/login')
async def login(user: User, Authorize: AuthJWT = Depends()):
    if user.username != "test" or user.password != "test":
        raise HTTPException(status_code=401, detail="Bad username or password")

    access_token = await  Authorize.create_access_token(subject=user.username)
    return {"access_token": access_token}
