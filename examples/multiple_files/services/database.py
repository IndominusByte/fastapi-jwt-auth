from sqlalchemy import MetaData
from databases import Database
from config import settings

metadata = MetaData()
database = Database(settings.db_url)
