from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import time

# ============================================================================
# Configuration
# ============================================================================
SECRET_KEY = "your-secret-key-change-this-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# ============================================================================
# FastAPI App
# ============================================================================
app = FastAPI(title="Kristina Backend API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # في الإنتاج، حدد النطاقات المسموح بها
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# Security
# ============================================================================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")

# ============================================================================
# Pydantic Models
# ============================================================================

# Service Info
class ServiceInfo(BaseModel):
    service: str = "kristina-backend-real"
    env: str = "dev"
    commit: str = "local"
    api_base: str = "/api"

# Dashboard Metrics
class KPI(BaseModel):
    label: str
    value: str

class TrendData(BaseModel):
    labels: List[str]
    values: List[float]

class DashboardMetrics(BaseModel):
    kpis: List[KPI]
    trend: TrendData

# Chat
class Message(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    messages: List[Message]

class ChatResponse(BaseModel):
    reply: str

# Authentication
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class User(BaseModel):
    username: str
    email: Optional[str] = None
    is_admin: bool = False

# ============================================================================
# Fake Database (للتطوير الأولي)
# ============================================================================
# Pre-hashed passwords (generated offline to avoid startup errors)
# password123 -> $2b$12$...
# admin123 -> $2b$12$...
fake_users_db = {
    "nasser": {
        "username": "nasser",
        "email": "nasser@example.com",
        "hashed_password": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyC.lfCXRqK2",  # password123
        "is_admin": False
    },
    "admin": {
        "username": "admin",
        "email": "admin@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # admin123
        "is_admin": True
    }
}

# ============================================================================
# Helper Functions
# ============================================================================

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(username: str, password: str):
    user = fake_users_db.get(username)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
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
    except JWTError:
        raise credentials_exception
    user = fake_users_db.get(username)
    if user is None:
        raise credentials_exception
    return User(**user)

# ============================================================================
# API Endpoints
# ============================================================================

# Health check
@app.get("/healthz")
async def healthz():
    return {"status": "ok", "ts": int(time.time())}

# Service version/info
@app.get("/api/version", response_model=ServiceInfo)
async def get_version():
    return ServiceInfo()

# Dashboard metrics
@app.get("/api/dashboard/metrics", response_model=DashboardMetrics)
async def get_dashboard_metrics():
    # بيانات تجريبية
    kpis = [
        KPI(label="المستخدمون النشطون", value="1,234"),
        KPI(label="الطلبات اليومية", value="5,678"),
        KPI(label="معدل النجاح", value="98.5%"),
        KPI(label="وقت الاستجابة", value="120ms"),
    ]
    trend = TrendData(
        labels=["الإثنين", "الثلاثاء", "الأربعاء", "الخميس", "الجمعة", "السبت", "الأحد"],
        values=[120, 150, 180, 160, 200, 220, 190]
    )
    return DashboardMetrics(kpis=kpis, trend=trend)

# Chat endpoint
@app.post("/api/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    # منطق دردشة بسيط (يمكن استبداله بـ AI حقيقي لاحقًا)
    last_user_message = next((m.content for m in reversed(request.messages) if m.role == "user"), "")
    reply = f"شكرًا لرسالتك: '{last_user_message}'. هذا رد تجريبي من الـ Backend الحقيقي. يمكن دمج نموذج AI هنا لاحقًا."
    return ChatResponse(reply=reply)

# Authentication endpoint
@app.post("/api/auth/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token)

# Get current user info (protected endpoint example)
@app.get("/api/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# Root endpoint
@app.get("/")
async def root():
    return {"message": "Kristina Backend API is running. Visit /docs for API documentation."}

