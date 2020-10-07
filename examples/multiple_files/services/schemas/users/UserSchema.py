from pydantic import BaseModel, EmailStr, constr

class UserSchema(BaseModel):
    class Config:
        min_anystr_length = 1
        max_anystr_length = 100
        anystr_strip_whitespace = True

class UserLogin(UserSchema):
    email: EmailStr
    password: constr(min_length=6)

class UserOut(UserSchema):
    email: EmailStr
    username: str

class UserUpdate(UserSchema):
    username: constr(min_length=3)
