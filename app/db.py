from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "sqlite:///./sql_app.db"

engine = create_engine(DATABASE_URL)

Session = sessionmaker(engine)

class Base(DeclarativeBase):
    pass

def get_db():
    db = Session()
    try:
        yield db
        db.commit()
    finally:
        db.close()

        