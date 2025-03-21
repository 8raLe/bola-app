## uvicorn app.main:app --reload

from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app.db import get_db, engine
from app.models.base import Base
from app.models.user import User
from app.models.product import Product
from app.models.order import Order
from app.security import get_password_hash, verify_password, get_current_user, create_access_token

app = FastAPI()

Base.metadata.create_all(bind=engine)

@app.get("/")
async def root():
    return {"message": "Hello, World!"}

# Login
@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=401,
            detail= "Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/register")
async def register_user(
        username: str, 
        email: str, 
        password: str, 
        is_admin: bool = False, # For Testing - Ordinarily this should probably be it's endpoint, as it's insecure
        db: Session = Depends(get_db)
    ):

    new_user = User(
        username=username,
        email=email,
        hashed_password=get_password_hash(password),
        is_admin=is_admin
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User created", "user_id": new_user.id}

# @app.post("/login")
# async def login(username: str, password: str, db: Session = Depends(get_db)):
#     user = db.query(User).filter(User.username == username).first()
#     if user and verify_password(password, user.hashed_password):
#         return {"message": "User Login", "user_id": user.id}
#     raise HTTPException(
#         status_code=401, # Unauthorised
#         detail= "Incorrect username or password"
#     )

# BOLA VULNERABILITY 1
# BOLA Issue: Anyone can view any user's details by changing the ID
# Fixed, 403 then 404.
##  403 first, then 404, helps protect information from attackers. Doesn't reveal if resource exists if not owned. 
# - However, does it make demonstration of BOLA more clear? ie. prioritising showing BOLA Breach, over fact resource does/does not exist. 

@app.get("/users/{user_id}")
async def get_user(
        user_id: int, 
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ):

    if user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=403, 
            detail="Unauthorised access"
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=404, 
            detail="User not found"
        )

    return {
        "id": user.id,
        "username": user.username,
        "email": user.email
    }

# BOLA VULNERABILITY 1 - Alternative Implementation 1
# Fixed, 404 then 403, reveals:
##  Reveals to attackers that resource (user_id) exists, if they can't access it. - Information Leakage! By observing 403 or 404 responses.

@app.get("/users/{user_id}/alt-path")
async def get_user2(
        user_id: int, 
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ):

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=404, 
            detail="User not found"
        )
    
    if not current_user.is_admin and current_user.id != user_id:
        raise HTTPException(
            status_code=403, 
            detail="Unauthorised access"
        )

    return {
        "id": user.id,
        "username": user.username,
        "email": user.email
    }

# BOLA VULNERABILITY 1 - Alternative Implementation 2
# Fixed, Security focused:
# Hides resource existence, querying only resources user is authorised to access, preventing enumeration attacks. Less helpful with error handling.

@app.get("/users/{user_id}/alt-path2")
async def get_user3(
        user_id: int, 
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ):

    if current_user.is_admin:
        user = db.query(User).filter(User.id == user_id).first()
    else:
        user = db.query(User).filter(
            User.id == user_id,
            User.id == current_user.id
        ).first()

    if not user:
        raise HTTPException(
            status_code=404, 
            detail="User not found"
        )
    
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email
    }


# In a real system, this would require checks to create products.
# Let's have none for the sake of testing.
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
# Fixed by allowing update only is Admin.

@app.put("/product/{product_id}")
async def update_product(
        product_id: int,
        name: str = None,
        description: str = None,
        price: float = None,
        stock: int = None,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ):
    
    # Fix here - Update Product only if Admin
    if not current_user.is_admin:
        raise HTTPException(
            status_code=403,
            detail="Unauthorised access"
        )
    
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
async def create_order(
        product_id: int, 
        order_amount: int, 
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ):

    # so users can only see their own orders and no one other user's
    user_id = current_user.id

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
# Fixed, Security-focued.

@app.get("/orders")
async def get_orders(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ):

    if current_user.is_admin:
        orders = db.query(Order).all()
    else:
        orders = db.query(Order).filter(Order.user_id == current_user.id).all()

    # if not orders:
    #     raise HTTPException(
    #         status_code=404, 
    #         detail="Order not found"
    #     )
    ## Return Empty List Instead - RESTful best practice
    
    return [{"user_id": o.user_id, "product id": o.product_id, "amount": o.amount, "status": o.status} for o in orders]



# BOLA VULNERABILITY 3
# BOLA Issue: Anyone can view any order's details just by knowing its ID
# Fixed, 404 then 403.

@app.get("/orders/{order_id}")
async def get_order(
        order_id: int, 
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ):
        
    order = db.query(Order).filter(Order.id == order_id).first()

    if not order:
        raise HTTPException(
            status_code=404, 
            detail="Order not found"
       )
    
    if not current_user.is_admin and current_user.id != order.user_id:
        raise HTTPException(
            status_code=403,
            detail="Unauthorised access"
        )
    
    return {
        "user_id": order.user_id,
        "product_id": order.product_id,
        "amount": order.amount,
        "status": order.status
    }

# BOLA VULNERABILITY 4
# Anyone can modify any order status
# Fixed, 404 then 403.

@app.put("/orders/{order_id}")
async def update_order(
        order_id: int, 
        status: str,
        current_user: User = Depends(get_current_user), 
        db: Session = Depends(get_db)
    ):

    order = db.query(Order).filter(Order.id == order_id).first()
    
    if not order:
        raise HTTPException(
            status_code=404, 
            detail="Order not found"
        )

    if not current_user.is_admin and current_user.id != order.user_id:
        raise HTTPException(
            status_code=403,
            detail="Unauthorised access"
        )

    # Security focused fix:
    # if current_user.is_admin:
    #     order = db.query(Order).filter(Order.id == order_id).first()
    # else:
    #     order = db.query(Order).filter(
    #         Order.id == order_id,
    #         Order.user_id == current_user.id
    #     ).first()

    # if not order:
    #     raise HTTPException(
    #         status_code=404, 
    #         detail="Order not found"
    #     )
    
    order.status = status
    db.commit()
    return {"message": "Order updated"}
    

# BOLA Vulnerability 6
# Anyone can access any user's orders just by changing the user_id
# Fixed, 403 then 404

@app.get("/users/{user_id}/orders")
async def get_user_orders(
        user_id: int,
        current_user: User = Depends(get_current_user), 
        db: Session = Depends(get_db)
    ):

    if not current_user.is_admin and current_user.id != user_id:
        raise HTTPException(
            status_code=403,
            detail="Unauthorised access"
        )
    
    orders = db.query(Order).filter(Order.user_id == user_id).all()

    if not orders:
        raise HTTPException(
            status_code=404,
            detail="User orders not found"
        )

    return [{
        "id": order.id, 
        "product_id": order.product_id, 
        "amount": order.amount, 
        "status": order.status
        } for order in orders]


# BOLA VULNERABILITY 7
# Anyone can delete any order
# Fixed, Security focused

@app.delete("/orders/{order_id}")
async def delete_order(
        order_id: int, 
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ):

    if current_user.is_admin:
        order = db.query(Order).filter(Order.id == order_id).first()
    else:
        order = db.query(Order).filter(
            Order.id == order_id,
            Order.user_id == current_user.id
        ).first()

    if not order:
        raise HTTPException(
            status_code=404, 
            detail="Order not found"
        )
            
    db.delete(order)
    db.commit()
    return {"message": "Order deleted"}