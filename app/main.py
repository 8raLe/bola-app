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

# BOLA VULNERABILITY 1
# BOLA Issue: Anyone can view any user's details by changing the ID
@app.get("/users/{user_id}")
async def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email
    }

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
    return {"message": "Product created", "product_id": new_product.id}

@app.get("/products")
async def list_products(db: Session = Depends(get_db)):
    products = db.query(Product).all() 
    return [{"id": p.id, "name": p.name, "price": p.price, "stock": p.stock} for p in products]

# BOLA VULNERABILITY 5
# Update Product only if Admin
@app.put("/product/{product_id}")
async def update_product(
    product_id: int,
    name: str = None,
    description: str = None,
    price: float = None,
    stock: int = None,
    db: Session = Depends(get_db)
):
    product = db.query(Product).filter(Product.id == product_id).first()
    if not product:
        raise HTTPException(
            status_code=404,
            detail="Product not found"
        )
    if name:
        product.name = name
    if description:
        product.description = description
    if price:
        product.price = price
    if stock:
        product.stock = stock

    db.commit()
    return{"message": "Product updated"}


@app.post("/orders")
async def create_order(user_id: int, product_id: int, order_amount: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    product = db.query(Product).filter(Product.id == product_id).first()

    if not user:
        raise HTTPException(
        status_code=400,
        detail= "User not found"
        )
    if not product:
        raise HTTPException(
            status_code=404,
            detail="Product not found"
        )
    if product.stock < order_amount:
        raise HTTPException(
            status_code=400,
            detail="Not enough stock"
        )
    
    product.stock -= order_amount
    new_order = Order(
        user_id = user_id,
        product_id = product_id,
        amount = order_amount,
        price = product.price,
        total_price = product.price * order_amount,
        status = "Pending"
        )
    db.add(new_order)
    db.commit()
    db.refresh(new_order)

    return {"message": "Order created", "order_id": new_order.id}

# BOLA VULNERABILITY 2
# All orders could be viewed regardless of ownership.
@app.get("/orders")
async def get_orders(db: Session = Depends(get_db)):
    orders = db.query(Order).all() # BOLA Vulnerability, as any user can see ALL
    return [{"user id": o.user_id, "product id": o.product_id, "amount": o.amount, "status": o.status} for o in orders]

# BOLA VULNERABILITY 3
# BOLA Issue: Anyone can view any order's details just by knowing its ID
@app.get("/orders/{orders_id}")
async def get_order(order_id: int, db: Session = Depends(get_db)):
    order = db.query(Order).filter(Order.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return {
        "user id": order.user_id,
        "product_id": order.product_id,
        "amount": order.amount,
        "status": order.status
    }

# BOLA VULNERABILITY 4
# Anyone can modify any order status
@app.put("orders/{order_id}")
async def update_order(order_id: int, status: str, db: Session = Depends(get_db)):
    order = db.query(Order).filter(Order.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    order.status = status
    db.commit()
    return {"message": "Order updated"}
    
# BOLA Vulnerability 6
# Anyone can access any user's orders just by changing the user_id in the URL
# No authentication check to verify if the requester is logged in
# No authorization check to verify if the requester is allowed to see these orders    
@app.get("users/{user_id}/orders")
async def get_user_orders(user_id: int, db: Session = Depends(get_db)):
    orders = db.query(Order).filter(Order.user_id == user_id).all()
    return [{
        "id": order.id, 
        "product_id": order.product_id, 
        "amount": order.amount, 
        "status": order.status
        } for order in orders]

# BOLA VULNERABILITY 7
# Anyone can delete any order
@app.delete("/orders/{order_id}")
async def delete_order(order_id: int, db: Session = Depends(get_db)):
    order = db.query(Order).filter(Order.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    db.delete(order)
    db.commit()
    return {"message": "Order deleted"}