## uvicorn app.main:app --reload

from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db import get_db, engine
from app.models.base import Base
from app.models.user import User
from app.models.product import Product
from app.models.order import Order
from app.security import get_password_hash, verify_password

app = FastAPI()

Base.metadata.create_all(bind=engine)

@app.get("/")
async def root():
    return {"message": "Hello, World!"}

@app.post("/register")
async def register_user(username: str, email: str, password: str, db: Session = Depends(get_db)):
    new_user = User(
        username=username,
        email=email,
        hashed_password=get_password_hash(password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User created", "user_id": new_user.id}

@app.post("/login")
async def login(username: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if user and verify_password(password, user.hashed_password):
        return {"message": "User Login", "user_id": user.id}
    raise HTTPException(
        status_code=401, # Unauthorised
        detail= "Incorrect username or password"
    )

@app.post("/products")
async def create_product(name: str, description: str, price: float, stock: int, db: Session = Depends(get_db)):
    new_product = Product(
        name=name,
        description=description,
        price=price,
        stock=stock
    )
    db.add(new_product)
    db.commit()
    db.refresh(new_product)
    return {"message": "Prodocut created", "product_id": new_product.id}

@app.get("/products")
async def list_products(db: Session = Depends(get_db)):
    products = db.query(Product).all()
    return [{"id": p.id, "name": p.name, "price": p.price} for p in products]

@app.post("/orders")
async def create_order(user_id: int, product_id: int, order_amount: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
        status_code=400,
        detail= "Bad request"
        )
    new_order = Order(
        user_id = user_id,
        product_id = product_id,
        amount = order_amount,
        status = "Pending"
        )
    db.add(new_order)
    db.commit()
    db.refresh(new_order)