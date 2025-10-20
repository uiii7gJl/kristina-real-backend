from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Float, func
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from datetime import datetime, timedelta
import os
import jwt
from passlib.context import CryptContext
from typing import Optional
from openai import OpenAI
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- FastAPI App Initialization ---
app = FastAPI()

# --- CORS Configuration ---
origins = [
    "http://localhost:3000",
    "http://localhost:5173",
    "https://mareekh-frontend.onrender.com",
    "https://mareekh-admin.onrender.com",
    "https://mareekh-user.onrender.com",
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
    success = Column(Boolean, default=True)
    response_time = Column(Float, default=0.0)

# --- Create Tables if Not Exists ---
Base.metadata.create_all(bind=engine)

# --- Dependency to get DB session ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Security (JWT) Configuration ---
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- OpenAI Client ---
openai_api_key = os.getenv("OPENAI_API_KEY")
openai_client = OpenAI(api_key=openai_api_key) if openai_api_key else None

# --- API Endpoints ---
@app.get("/", tags=["Health Check"])
async def root():
    return {"message": "Welcome to Kristina Backend!"}

@app.get("/api/version", tags=["Health Check"])
async def get_version():
    return {"version": "1.0.0", "status": "ok"}

# --- Dashboard Metrics (Dynamic) ---
@app.get("/api/dashboard/metrics", tags=["Dashboard"])
async def get_dashboard_metrics(db: Session = Depends(get_db)):
    total_active_users = db.query(User).filter(User.is_active==True).count()
    today = datetime.utcnow().date()
    daily_requests = db.query(Activity).filter(Activity.timestamp >= today).count()
    success_avg = db.query(Activity).filter(Activity.timestamp >= today).with_entities(func.avg(Activity.success.cast(Float))).scalar() or 0
    avg_response = db.query(Activity).filter(Activity.timestamp >= today).with_entities(func.avg(Activity.response_time)).scalar() or 0

    metrics = [
        {"label": "المستخدمون النشطون", "value": total_active_users},
        {"label": "الطلبات اليومية", "value": daily_requests},
        {"label": "معدل النجاح", "value": round(success_avg*100, 2)},  # %
        {"label": "وقت الاستجابة", "value": round(avg_response, 2)},  # بالثواني
    ]
    return metrics

# --- AI Chat ---
@app.post("/api/chat", tags=["AI Chat"])
async def chat_with_ai(message: dict):
    if not openai_client:
        raise HTTPException(status_code=503, detail="AI chat service not available. OPENAI_API_KEY missing.")

    user_content = message.get("messages") or message.get("message")
    if not user_content:
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    try:
        response = openai_client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": "أنت مساعد ذكاء اصطناعي مفيد."},
                {"role": "user", "content": user_content},
            ]
        )
        ai_response = response.choices[0].message.content
        return {"reply": ai_response}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI chat error: {str(e)}")
