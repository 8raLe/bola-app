from sqlalchemy import Column, String, Boolean
from app.models.base import BaseModel

class User(BaseModel):
    __tablename__ = "users"

    email = Column(String, unique=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_admin = Column(Boolean, default=False)