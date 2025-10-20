from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Float
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from datetime import datetime, timedelta
import os
import jwt
from passlib.context import CryptContext
import logging
from typing import Optional
from openai import OpenAI

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- FastAPI App Initialization ---
app = FastAPI()

# --- CORS Configuration (allow all origins temporarily) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # مؤقت للتأكد من عمل OPTIONS و POST
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

# Create tables
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
    logger.warning("OPENAI_API_KEY not set. Chat will be disabled.")
    openai_client = None
else:
    openai_client = OpenAI(api_key=openai_api_key)

# --- API Endpoints ---
@app.get("/", tags=["Health Check"])
async def root():
    return {"message": "Welcome to Mareekh/Kristina Backend!"}

@app.get("/api/version", tags=["Health Check"])
async def get_version():
    return {"version": "1.0.0", "status": "ok"}

@app.get("/health", tags=["Health Check"])
async def health_check():
    return {"status": "ok", "message": "Backend is healthy"}

# --- Dashboard Metrics ---
dummy_metrics_data = [
    {"name": "Total Users", "value": 1250, "unit": "users"},
    {"name": "Active Sessions", "value": 340, "unit": "sessions"},
    {"name": "Avg. Response Time", "value": 1.2, "unit": "s"},
    {"name": "Error Rate", "value": 0.5, "unit": "%"},
]

@app.get("/api/dashboard/metrics", tags=["Dashboard"])
async def get_dashboard_metrics(db: Session = Depends(get_db)):
    metrics = db.query(DashboardMetric).all()
    if not metrics:
        logger.info("No dashboard metrics found. Populating dummy data.")
        for data in dummy_metrics_data:
            metric = DashboardMetric(**data)
            db.add(metric)
        db.commit()
        metrics = db.query(DashboardMetric).all()
    # تحويل البيانات لتتناسب مع React frontend
    return [{"label": metric.name, "value": metric.value} for metric in metrics]

# --- Chat Endpoint ---
@app.post("/api/chat", tags=["AI Chat"])
async def chat_with_ai(payload: dict):
    if not openai_client:
        raise HTTPException(status_code=503, detail="AI chat service unavailable")

    # إما {messages: [...] } أو {message: "text"}
    messages_list = payload.get("messages")
    if messages_list is None:
        single_msg = payload.get("message")
        if single_msg:
            messages_list = [{"role": "user", "content": single_msg}]
        else:
            raise HTTPException(status_code=400, detail="No messages provided")

    user_content = "\n".join([m["content"] for m in messages_list if m["role"]=="user"])
    try:
        response = openai_client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": "أنت مساعد ذكاء اصطناعي مفيد."},
                {"role": "user", "content": user_content}
            ]
        )
        return {"reply": response.choices[0].message.content}
    except Exception as e:
        logger.error(f"AI chat error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"AI chat error: {str(e)}")
