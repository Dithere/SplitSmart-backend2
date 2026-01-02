from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from sqlalchemy.sql import func
from pydantic import BaseModel
from typing import List
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import jwt, JWTError
from dotenv import load_dotenv
import os
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")
# --- DATABASE SETUP ---
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=0,
)


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    name = Column(String(100))
    email = Column(String(150), unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    push_token = Column(String, nullable=True)  # 👈 ADD


class Group(Base):
    __tablename__ = "groups"

    id = Column(Integer, primary_key=True)
    name = Column(String(100))
    created_by = Column(Integer, ForeignKey("users.id"))


class GroupMember(Base):
    __tablename__ = "group_members"

    id = Column(Integer, primary_key=True)
    group_id = Column(Integer, ForeignKey("groups.id"))
    user_id = Column(Integer, ForeignKey("users.id"))


class Expense(Base):
    __tablename__ = "expenses"

    id = Column(Integer, primary_key=True)
    group_id = Column(Integer, ForeignKey("groups.id"))
    paid_by = Column(Integer, ForeignKey("users.id"))
    amount = Column(Float)
    description = Column(String(255))
    created_at = Column(DateTime, server_default=func.now())


class ExpenseSplit(Base):
    __tablename__ = "expense_splits"

    id = Column(Integer, primary_key=True)
    expense_id = Column(Integer, ForeignKey("expenses.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    share_amount = Column(Float)


class Balance(Base):
    __tablename__ = "balances"

    id = Column(Integer, primary_key=True)
    group_id = Column(Integer, ForeignKey("groups.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    balance = Column(Float, default=0.0)
class Settlement(Base):
    __tablename__ = "settlements"

    id = Column(Integer, primary_key=True)
    from_user = Column(Integer, ForeignKey("users.id"))
    to_user = Column(Integer, ForeignKey("users.id"))
    amount = Column(Float)
    created_at = Column(DateTime, server_default=func.now())


# --- FASTAPI SETUP ---
app = FastAPI()
origins = [
    "http://localhost:3000",  # your frontend
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "https://splitsmart-backend2.onrender.com",
        "http://localhost:8001"
        ],          # allow your frontend
    allow_credentials=True,
    allow_methods=["*"],            # GET, POST, etc.
    allow_headers=["*"],            # allow all headers
)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

import hashlib

def hash_password(password: str) -> str:
    return password

def verify_password(password: str, hashed: str) -> bool:
    return password == hashed

def create_access_token(data: dict):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # JWT 'sub' must be a string; ensure the user ID is cast to str
    to_encode = data.copy()
    to_encode.update({"exp": expire, "sub": str(data.get("sub"))})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id_str: str = payload.get("sub")
        if user_id_str is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return int(user_id_str) # Cast back to int for your SQLAlchemy queries
    except (JWTError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token")
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    user_id = verify_token(token)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

class RegisterSchema(BaseModel):
    name: str
    email: str
    password: str


class LoginSchema(BaseModel):
    email: str
    password: str


class GroupCreate(BaseModel):
    name: str


class ExpenseCreate(BaseModel):
    group_id: int
    amount: float
    description: str
    split_between: List[int]
class AddMemberSchema(BaseModel):
    user_id: int
class SettleSchema(BaseModel):
    group_id: int
    to_user_id: int
    amount: float
class PushTokenSchema(BaseModel):
    push_token: str

@app.post("/me/push-token")
def save_push_token(
    data: PushTokenSchema,
    user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user.push_token = data.push_token
    db.commit()
    return {"msg": "Token saved"}


@app.post("/register")
def register(data: RegisterSchema, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == data.email).first()
    if existing:
        raise HTTPException(400, "Email already registered")

    user = User(
        name=data.name,
        email=data.email,
        password_hash=hash_password(data.password)
    )

    db.add(user)
    db.commit()
    return {"msg": "User registered"}


@app.post("/login")
def login(data: LoginSchema, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": user.id})
    return {"access_token": token, "token_type": "bearer"}
@app.post("/groups")
def create_group(data: GroupCreate, user=Depends(get_current_user), db: Session = Depends(get_db)):
    group = Group(name=data.name, created_by=user.id)
    db.add(group)
    db.commit()

    db.add(GroupMember(group_id=group.id, user_id=user.id))
    db.add(Balance(group_id=group.id, user_id=user.id, balance=0))
    db.commit()

    return {"group_id": group.id}

class Notification(Base):
    __tablename__ = "notifications"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    message = Column(String(255))
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=func.now())
def send_push_notification(token: str, title: str, body: str, data: dict | None = None):
    payload = {
        "to": token,
        "title": title,
        "body": body,
        "sound": "default",
        "data": data or {}
    }
    requests.post("https://exp.host/--/api/v2/push/send", json=payload)


@app.post("/expenses")
def add_expense(
    data: ExpenseCreate,
    user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # 1️⃣ Create expense
    expense = Expense(
        group_id=data.group_id,
        paid_by=user.id,
        amount=data.amount,
        description=data.description
    )
    db.add(expense)
    db.commit()
    db.refresh(expense)

    # 2️⃣ Split logic
    share = data.amount / len(data.split_between)

    for uid in data.split_between:
        db.add(ExpenseSplit(
            expense_id=expense.id,
            user_id=uid,
            share_amount=share
        ))

        balance = (
            db.query(Balance)
            .filter_by(group_id=data.group_id, user_id=uid)
            .first()
        )

        if not balance:
            balance = Balance(group_id=data.group_id, user_id=uid, balance=0)
            db.add(balance)

        if uid == user.id:
            balance.balance += data.amount - share
        else:
            balance.balance -= share

    db.commit()

    # 3️⃣ 🔔 NOTIFICATIONS (DB + PUSH)
    members = (
        db.query(User)
        .join(GroupMember, GroupMember.user_id == User.id)
        .filter(
            GroupMember.group_id == data.group_id,
            User.id != user.id
        )
        .all()
    )

    for member in members:
        message = f"{user.name} added ₹{data.amount} ({data.description})"

        # save notification in DB
        db.add(Notification(
            user_id=member.id,
            message=message
        ))

        # send push notification
        if member.push_token:
            try:
                send_push_notification(
                    token=member.push_token,
                    title="New Expense Added 💸",
                    body=message,
                    data={"groupId": data.group_id}
                )
            except Exception as e:
                print("Push failed:", e)


    db.commit()

    return {"msg": "Expense added"}

@app.get("/groups/{group_id}/balances")
def group_balances(group_id: int, user=Depends(get_current_user), db: Session = Depends(get_db)):
    balances = db.query(Balance).filter_by(group_id=group_id).all()
    return balances
@app.post("/groups/{group_id}/add-member")
def add_member(
    group_id: int,
    data: AddMemberSchema,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # check group exists
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(404, "Group not found")

    # only group creator can add
    if group.created_by != current_user.id:
        raise HTTPException(403, "Not allowed")

    # check user exists
    user = db.query(User).filter(User.id == data.user_id).first()
    if not user:
        raise HTTPException(404, "User not found")

    # prevent duplicate entry
    exists = db.query(GroupMember).filter_by(
        group_id=group_id,
        user_id=data.user_id
    ).first()

    if exists:
        raise HTTPException(400, "User already in group")

    db.add(GroupMember(group_id=group_id, user_id=data.user_id))
    db.add(Balance(group_id=group_id, user_id=data.user_id, balance=0))
    db.commit()

    return {"msg": "User added to group"}
@app.get("/me/dashboard")
def dashboard(
    user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    group_count = db.query(GroupMember)\
                    .filter_by(user_id=user.id)\
                    .count()

    total_owe = db.query(Balance)\
                  .filter(Balance.user_id == user.id, Balance.balance < 0)\
                  .all()

    total_get = db.query(Balance)\
                  .filter(Balance.user_id == user.id, Balance.balance > 0)\
                  .all()

    return {
        "groups": group_count,
        "you_owe": abs(sum(b.balance for b in total_owe)),
        "you_get": sum(b.balance for b in total_get)
    }
@app.get("/net-owe/{other_user_id}")
def net_owe(
    other_user_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # groups both users are part of
    shared_groups = (
        db.query(Balance.group_id)
        .filter(Balance.user_id == current_user.id)
        .intersect(
            db.query(Balance.group_id)
            .filter(Balance.user_id == other_user_id)
        )
        .all()
    )

    net = 0.0

    for (group_id,) in shared_groups:
        me = db.query(Balance).filter_by(
            group_id=group_id,
            user_id=current_user.id
        ).first()

        other = db.query(Balance).filter_by(
            group_id=group_id,
            user_id=other_user_id
        ).first()

        net += me.balance
        net -= other.balance

    return {
        "with_user": other_user_id,
        "net_amount": round(net, 2),
        "status": (
            "you_get" if net > 0 else
            "you_owe" if net < 0 else
            "settled"
        )
    }
@app.post("/settle")
def settle_up(
    data: SettleSchema,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    member = db.query(GroupMember).filter_by(
    group_id=data.group_id,
    user_id=current_user.id
    ).first()

    if not member:
        raise HTTPException(403, "Not a group member")

   

    if data.amount <= 0:
        raise HTTPException(400, "Invalid amount")

    settlement = Settlement(
        from_user=current_user.id,
        to_user=data.to_user_id,
        amount=data.amount
    )
    db.add(settlement)

    me = db.query(Balance).filter_by(
        group_id=data.group_id,
        user_id=current_user.id
    ).first()

    other = db.query(Balance).filter_by(
        group_id=data.group_id,
        user_id=data.to_user_id
    ).first()

    if not me or not other:
        raise HTTPException(400, "Invalid group or users")

    me.balance += data.amount
    other.balance -= data.amount

    db.commit()
    return {"msg": "Settlement successful"}

@app.get("/groups/{group_id}/net-owe")
def group_net_owe(
    group_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Check membership
    member = db.query(GroupMember).filter_by(
        group_id=group_id,
        user_id=current_user.id
    ).first()

    if not member:
        raise HTTPException(403, "Not a group member")

    # Your balance
    my_balance = db.query(Balance).filter_by(
        group_id=group_id,
        user_id=current_user.id
    ).first()

    if not my_balance:
        return {"group_id": group_id, "net": []}

    # All other members
    others = (
        db.query(Balance, User)
        .join(User, Balance.user_id == User.id)
        .filter(
            Balance.group_id == group_id,
            Balance.user_id != current_user.id
        )
        .all()
    )

    result = []

    for balance, user in others:
        net = my_balance.balance - balance.balance

        if net == 0:
            status = "settled"
        elif net > 0:
            status = "you_get"
        else:
            status = "you_owe"

        result.append({
            "user_id": user.id,
            "name": user.name,
            "net_amount": round(abs(net), 2),
            "status": status
        })

    return {
        "group_id": group_id,
        "net_owe": result
    }
@app.get("/groups/{group_id}/settle-suggestions")
def settle_suggestions(
    group_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # ensure user is member
    member = db.query(GroupMember).filter_by(
        group_id=group_id,
        user_id=current_user.id
    ).first()

    if not member:
        raise HTTPException(403, "Not a group member")

    balances = (
        db.query(Balance, User)
        .join(User, Balance.user_id == User.id)
        .filter(Balance.group_id == group_id)
        .all()
    )

    creditors = []  # (user_id, name, amount)
    debtors = []    # (user_id, name, amount)

    for bal, user in balances:
        if bal.balance > 0:
            creditors.append([user.id, user.name, bal.balance])
        elif bal.balance < 0:
            debtors.append([user.id, user.name, abs(bal.balance)])

    i = j = 0
    settlements = []

    while i < len(debtors) and j < len(creditors):
        debtor = debtors[i]
        creditor = creditors[j]

        settle_amount = min(debtor[2], creditor[2])

        settlements.append({
            "from_user_id": debtor[0],
            "from_name": debtor[1],
            "to_user_id": creditor[0],
            "to_name": creditor[1],
            "amount": round(settle_amount, 2)
        })

        debtor[2] -= settle_amount
        creditor[2] -= settle_amount

        if debtor[2] == 0:
            i += 1
        if creditor[2] == 0:
            j += 1

    return {
        "group_id": group_id,
        "transactions": settlements
    }
@app.get("/me/groups")
def my_groups(
    user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    groups = (
        db.query(Group)
        .join(GroupMember)
        .filter(GroupMember.user_id == user.id)
        .all()
    )
    return groups
@app.get("/groups/{group_id}")
def group_details(group_id: int, user=Depends(get_current_user), db: Session = Depends(get_db)):
    member = db.query(GroupMember).filter_by(group_id=group_id, user_id=user.id).first()
    if not member:
        raise HTTPException(403, "Not a group member")

    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(404, "Group not found")

    members = db.query(User.id, User.name, User.email).join(GroupMember).filter(GroupMember.group_id == group_id).all()

    # Explicitly format members to be JSON serializable
    return {
        "group_id": group.id,
        "name": group.name,
        "members": [{"id": m.id, "name": m.name, "email": m.email} for m in members]
    }
@app.get("/groups/{group_id}/expenses")
def group_expenses(
    group_id: int,
    user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    member = db.query(GroupMember).filter_by(
        group_id=group_id,
        user_id=user.id
    ).first()

    if not member:
        raise HTTPException(403, "Not a group member")

    expenses = (
        db.query(Expense, User.name)
        .join(User, Expense.paid_by == User.id)
        .filter(Expense.group_id == group_id)
        .order_by(Expense.created_at.desc())
        .all()
    )

    return [
        {
            "id": e.id,
            "amount": e.amount,
            "description": e.description,
            "paid_by": name,
            "created_at": e.created_at
        }
        for e, name in expenses
    ]
@app.get("/users/search")
def search_users(
    q: str,
    user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    users = db.query(User)\
        .filter(User.email.ilike(f"%{q}%"))\
        .limit(10)\
        .all()

    return [{"id": u.id, "name": u.name, "email": u.email} for u in users]
@app.delete("/groups/{group_id}/leave")
def leave_group(
    group_id: int,
    user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    balance = db.query(Balance).filter_by(
        group_id=group_id,
        user_id=user.id
    ).first()

    if balance and balance.balance != 0:
        raise HTTPException(400, "Settle balance before leaving")

    db.query(GroupMember).filter_by(
        group_id=group_id,
        user_id=user.id
    ).delete()

    db.query(Balance).filter_by(
        group_id=group_id,
        user_id=user.id
    ).delete()

    db.commit()
    return {"msg": "Left group"}
@app.get("/me/activity")
def activity_feed(
    user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    expenses = (
        db.query(Expense, Group.name, User.name)
        .join(Group, Expense.group_id == Group.id)
        .join(User, Expense.paid_by == User.id)
        .join(GroupMember, GroupMember.group_id == Group.id)
        .filter(GroupMember.user_id == user.id)
        .order_by(Expense.created_at.desc())
        .limit(30)
        .all()
    )

    return [
        {
            "type": "expense",
            "group": group_name,
            "paid_by": paid_by,
            "amount": expense.amount,
            "description": expense.description,
            "created_at": expense.created_at
        }
        for expense, group_name, paid_by in expenses
    ]

@app.get("/me/notifications")
def get_notifications(user=Depends(get_current_user), db=Depends(get_db)):
    return db.query(Notification)\
        .filter(Notification.user_id == user.id)\
        .order_by(Notification.created_at.desc())\
        .all()
import requests

@app.post("/me/notifications/{id}/read")
def mark_read(id: int, user=Depends(get_current_user), db=Depends(get_db)):
    n = db.query(Notification).filter_by(id=id, user_id=user.id).first()
    if not n:
        raise HTTPException(404)
    n.is_read = True
    db.commit()
    return {"msg": "Read"}
@app.get("/me/analytics/monthly")
def monthly_analytics(
    user=Depends(get_current_user),
    db=Depends(get_db)
):
    expenses = (
        db.query(func.date_trunc('month', Expense.created_at), func.sum(Expense.amount))
        .filter(Expense.paid_by == user.id)
        .group_by(func.date_trunc('month', Expense.created_at))
        .all()
    )

    return [{"month": m, "total": float(t)} for m, t in expenses]
@app.get("/me/simplify-debts")
def simplify_debts(user=Depends(get_current_user), db=Depends(get_db)):
    balances = db.query(Balance).filter(Balance.user_id == user.id).all()

    total = sum(b.balance for b in balances)
    return {
        "net_position": round(total, 2),
        "status": "you_get" if total > 0 else "you_owe"
    }


if __name__ == "__main__":
    import uvicorn
    print("Starting server at http://localhost:8000 jjjj")
    uvicorn.run(app, host="0.0.0.0", port=8000)
