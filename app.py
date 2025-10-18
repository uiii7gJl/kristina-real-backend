# -*- coding: utf-8 -*-
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Float
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.sql import func
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import os
import jwt
from passlib.context import CryptContext
from typing import Optional
from openai import OpenAI

# --- FastAPI App Initialization ---
app = FastAPI()

# --- CORS Configuration ---
origins = [
    "http://localhost:3000",  # Frontend local development
    "http://localhost:5173",  # Frontend local development (Vite default )
    "https://mareekh-frontend.onrender.com", # Example Render frontend URL
    "https://mareekh-admin.onrender.com", # Example Render admin URL
    "https://mareekh-user.onrender.com", # Example Render user URL
    # Add other frontend URLs as needed
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
 )

# --- Database Configuration ---
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable not set")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Database Models ---
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)

class Activity(Base):
    __tablename__ = "activities"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    activity_type = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    details = Column(String, nullable=True)

class DashboardMetric(Base):
    __tablename__ = "dashboard_metrics"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    value = Column(Float)
    unit = Column(String, nullable=True)
    last_updated = Column(DateTime, default=datetime.utcnow)

# Create database tables
Base.metadata.create_all(bind=engine)

# --- Dependency to get DB session ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Security (JWT) Configuration ---
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key") # Use a strong, random key in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- OpenAI Client ---
openai_api_key = os.getenv("OPENAI_API_KEY")
if not openai_api_key:
    print("Warning: OPENAI_API_KEY environment variable not set. Chat functionality will be disabled.")
    openai_client = None
else:
    openai_client = OpenAI(api_key=openai_api_key)

# --- API Endpoints ---

@app.get("/", tags=["Health Check"])
async def root():
    return {"message": "Welcome to Mareekh/Kristina Backend!"}

@app.get("/health", tags=["Health Check"])
async def health_check():
    return {"status": "ok", "message": "Backend is healthy"}

@app.get("/metrics", tags=["Dashboard"])
async def get_dashboard_metrics(db: Session = Depends(get_db)):
    metrics = db.query(DashboardMetric).all()
    if not metrics:
        # Populate with some dummy data if no metrics exist
        if os.getenv("POPULATE_DUMMY_DATA", "false").lower() == "true":
            dummy_metrics_data = [
                {"name": "Total Users", "value": 1250, "unit": "users"},
                {"name": "Active Sessions", "value": 340, "unit": "sessions"},
                {"name": "Avg. Response Time", "value": 1.2, "unit": "s"},
                {"name": "Error Rate", "value": 0.5, "unit": "%"},
            ]
            for data in dummy_metrics_data:
                metric = DashboardMetric(**data)
                db.add(metric)
            db.commit()
            metrics = db.query(DashboardMetric).all()
        else:
            raise HTTPException(status_code=404, detail="No dashboard metrics found. Set POPULATE_DUMMY_DATA=true to generate dummy data.")

    return [{
        "name": metric.name,
        "value": metric.value,
        "unit": metric.unit,
        "last_updated": metric.last_updated.isoformat()
    } for metric in metrics]

@app.post("/chat", tags=["AI Chat"])
async def chat_with_ai(message: dict):
    if not openai_client:
        raise HTTPException(status_code=503, detail="AI chat service is not available. OPENAI_API_KEY is missing.")

    user_message = message.get("message")
    if not user_message:
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    try:
        response = openai_client.chat.completions.create(
            model="gpt-4.1-mini", # Using the suggested model from the prompt
            messages=[
                {"role": "system", "content": "أنت مساعد ذكاء اصطناعي مفيد."},
                {"role": "user", "content": user_message}
            ]
        )
        ai_response = response.choices[0].message.content
        return {"response": ai_response}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI chat error: {str(e)}")

# Example of a protected endpoint (requires authentication)
# @app.get("/users/me", tags=["Users"])
# async def read_users_me(current_user: User = Depends(get_current_active_user)):
#     return current_user

# You would also need authentication endpoints like /token to generate JWTs
# and a dependency for get_current_active_user that decodes the JWT.
# For brevity, these are omitted but would be part of a full implementation.

# To run this file locally:
# pip install fastapi uvicorn sqlalchemy psycopg2-binary python-jose passlib openai
# uvicorn app:app --reload --host 0.0.0.0 --port 8000
# Make sure to set environment variables: DATABASE_URL, OPENAI_API_KEY, SECRET_KEY

