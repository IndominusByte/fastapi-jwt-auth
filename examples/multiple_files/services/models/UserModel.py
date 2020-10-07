from database import metadata
from sqlalchemy import Table, Column, Integer, String

users = Table("users", metadata,
    Column('id', Integer, primary_key=True),
    Column('username', String(100), nullable=False),
    Column('email', String(100), unique=True, index=True, nullable=False),
    Column('password', String(100), nullable=False),
    Column('role', Integer, default=1)
)
