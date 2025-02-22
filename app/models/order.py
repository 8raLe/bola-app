from sqlalchemy import Column, String, Integer, Float, ForeignKey
from sqlalchemy.orm import relationship
from app.models.base import BaseModel

class Order(BaseModel):
    __tablename__ = "orders"

    user_id = Column(Integer, ForeignKey("users.id"))
    product_id = Column(Integer, ForeignKey("products.id"))
    amount = Column(Integer)
    price = Column(Float)
    total_price = Column(Float)

    status = Column(String) # pending / completed
    

    # BOLA Vulnerability?
    user = relationship("User")