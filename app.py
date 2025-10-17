# -*- coding: utf-8 -*-
import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field # Import Field
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional, List
import openai
import os

# SQLAlchemy Imports
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.sql import func

# --- Configuration ---
SECRET_KEY = os.environ.get("SECRET_KEY", "a-very-secret-key-that-you-should-replace")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OpenAI API Key
openai.api_key = os.environ.get("OPENAI_API_KEY")

# Database Configuration
DATABASE_URL = os.environ.get("DATABASE_URL")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- SQLAlchemy Models ---
class DBUser(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True)
    full_name = Column(String)
    hashed_password = Column(String, nullable=False)
    disabled = Column(Boolean, default=False)

class DBDashboardMetric(Base):
    __tablename__ = "dashboard_metrics"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    value = Column(String)
    change = Column(String)

class DBRecentActivity(Base):
    __tablename__ = "recent_activities"
    id = Column(Integer, primary_key=True, index=True)
    user = Column(String)
    action = Column(String)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

class DBChartData(Base):
    __tablename__ = "chart_data"
    id = Column(Integer, primary_key=True, index=True)
    labels = Column(JSON)
    values = Column(JSON)


# --- FastAPI App Initialization ---
app = FastAPI()

@app.on_event("startup")
def on_startup():
    # Create database tables if they don\\'t exist
    Base.metadata.create_all(bind=engine)

# --- Dependencies ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Security & Auth ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(db: Session, username: str):
    return db.query(DBUser).filter(DBUser.username == username).first()

async def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(db, token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: "User" = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# --- Pydantic Models (Schemas) ---
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class UserBase(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None

class UserCreate(UserBase):
    password: str

class User(UserBase):
    disabled: Optional[bool] = None
    class Config:
        from_attributes = True

class DashboardMetric(BaseModel):
    title: str
    value: str
    change: str
    class Config:
        from_attributes = True

class RecentActivity(BaseModel):
    user: str
    action: str
    timestamp: datetime
    class Config:
        from_attributes = True

class ChartData(BaseModel):
    # Explicitly define fields for Pydantic to handle JSON columns
    labels: List[str] = Field(default_factory=list)
    values: List[int] = Field(default_factory=list)
    class Config:
        from_attributes = True

class DashboardData(BaseModel):
    metrics: List[DashboardMetric]
    recent_activities: List[RecentActivity]
    performance_chart: Optional[ChartData] = None

class Message(BaseModel):
    role: str
    content: str

class ChatInput(BaseModel):
    messages: List[Message]

# --- Middleware ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# --- API Endpoints ---
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = get_user(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/register", response_model=User)
async def register_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(DBUser).filter(DBUser.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
    db_user = DBUser(username=user.username, email=user.email, full_name=user.full_name, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

@app.get("/api/dashboard", response_model=DashboardData)
async def get_dashboard_data(db: Session = Depends(get_db)):
    metrics = db.query(DBDashboardMetric).all()
    recent_activities = db.query(DBRecentActivity).order_by(DBRecentActivity.timestamp.desc()).limit(5).all()
    performance_chart = db.query(DBChartData).first()
    return DashboardData(
        metrics=metrics,
        recent_activities=recent_activities,
        performance_chart=performance_chart
    )

@app.post("/api/chat")
async def chat_with_gpt(chat_input: ChatInput):
    if not openai.api_key:
        raise HTTPException(status_code=500, detail="OpenAI API key is not configured")
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[msg.dict() for msg in chat_input.messages]
        )
        return response.choices[0].message.content
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
def read_root():
    return {"message": "Welcome to the Kristina Real Backend"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
