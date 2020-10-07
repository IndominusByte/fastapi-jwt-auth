import bcrypt
from sqlalchemy import select
from fastapi import HTTPException
from models.UserModel import users
from database import database

class UserLogic:
    def check_user_password(password: str, hashed_pass: str) -> bool:
        return bcrypt.checkpw(password.encode(), hashed_pass.encode())

class UserCrud:
    async def create_user(**kwargs) -> int:
        email_exists = await UserFetch.filter_by_email(kwargs['email'])
        hashed_pass = bcrypt.hashpw(kwargs['password'].encode(), bcrypt.gensalt())
        kwargs.update({'password': hashed_pass.decode('utf-8')})
        if email_exists is None:
            return await database.execute(query=users.insert(),values=kwargs)
        raise HTTPException(status_code=400,detail="User already exists")

    async def update_user(user_id: int, **kwargs) -> None:
        query = users.update().where(users.c.id == user_id).values(**kwargs)
        await database.execute(query=query)

    async def delete_user(user_id: int) -> int:
        user_exists = await UserFetch.filter_by_id(id=user_id)
        if user_exists:
            return await database.execute(query=users.delete().where(users.c.id == user_id))
        raise HTTPException(status_code=400,detail="User not found!")

class UserFetch:
    async def all_user() -> users:
        return await database.fetch_all(query=select([users]))

    async def filter_by_email(email: str) -> users:
        query = select([users]).where(users.c.email == email)
        return await database.fetch_one(query=query)

    async def filter_by_id(id: int) -> users:
        query = select([users]).where(users.c.id == id)
        return await database.fetch_one(query=query)
