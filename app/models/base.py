from app.db import Base
from sqlalchemy import Column, Integer, DateTime
from datetime import datetime, UTC


class BaseModel(Base):
    __abstract__ = True

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=datetime.now(UTC))
    updated_at = Column(DateTime, default=datetime.now(UTC),  onupdate=datetime.now(UTC))