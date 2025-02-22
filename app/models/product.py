from sqlalchemy import Column, String, Float, Integer
from app.models.base import BaseModel

class Product(BaseModel):
    __tablename__ = "products"

    name = Column(String, unique=True, index=True)
    description = Column(String)
    price = Column(Float)
    stock = Column(Integer)