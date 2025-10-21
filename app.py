from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Float, func, cast
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from datetime import datetime, timedelta, date
import os
import jwt
from passlib.context import CryptContext
from typing import Optional
from openai import OpenAI
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- FastAPI App ---
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

# --- Models ---
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

Base.metadata.create_all(bind=engine)

# --- DB Session ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Security ---
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key")
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password): return pwd_context.hash(password)
def verify_password(plain, hashed): return pwd_context.verify(plain, hashed)
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=30))
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

# --- OpenAI ---
openai_api_key = os.getenv("OPENAI_API_KEY")
openai_client = OpenAI(api_key=openai_api_key) if openai_api_key else None

# --- Routes ---
@app.get("/", tags=["Health Check"])
async def root():
    return {"message": "Kristina Backend Active"}

@app.get("/api/version", tags=["Health Check"])
async def version():
    return {"version": "1.0.0", "status": "ok"}

@app.get("/api/dashboard/metrics", tags=["Dashboard"])
async def get_metrics(db: Session = Depends(get_db)):
    today = date.today()

    total_active_users = db.query(User).filter(User.is_active == True).count()
    daily_requests = db.query(Activity).filter(Activity.timestamp >= today).count()
    success_avg = db.query(func.avg(cast(Activity.success, Integer))).filter(Activity.timestamp >= today).scalar() or 0
    avg_response = db.query(func.avg(Activity.response_time)).filter(Activity.timestamp >= today).scalar() or 0

    metrics = [
        {"label": "المستخدمون النشطون", "value": total_active_users},
        {"label": "الطلبات اليومية", "value": daily_requests},
        {"label": "معدل النجاح", "value": round(success_avg * 100, 2)},
        {"label": "وقت الاستجابة", "value": round(avg_response, 2)},
    ]
    return metrics

@app.post("/api/chat", tags=["AI Chat"])
async def chat(message: dict):
    if not openai_client:
        raise HTTPException(status_code=503, detail="OPENAI_API_KEY missing or invalid")

    content = message.get("message")
    if not content:
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    try:
        response = openai_client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": "أنت مساعد ذكاء اصطناعي تابع لمنصة Kristina. أجب فقط عن الأسئلة المتعلقة بالموقع ووظائفه."},
                {"role": "user", "content": content},
            ],
        )
        return {"reply": response.choices[0].message.content}
    except Exception as e:
        logger.error(f"Chat error: {e}")
        raise HTTPException(status_code=500, detail=f"Chat error: {str(e)}")
