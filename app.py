from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import time
import os

# 1. استيراد مكتبة OpenAI
from openai import OpenAI

# ============================================================================
# Configuration
# ============================================================================
SECRET_KEY = "your-secret-key-change-this-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# 2. تهيئة عميل OpenAI
# سيتم قراءة OPENAI_API_KEY تلقائيًا من متغيرات البيئة في Render
client = OpenAI()

# ============================================================================
# FastAPI App
# ============================================================================
app = FastAPI(title="Kristina Backend API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # في الإنتاج، يجب تحديد النطاقات المسموح بها
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# Pydantic Models (نماذج البيانات)
# ============================================================================

class ServiceInfo(BaseModel):
    service: str = "kristina-backend-real"
    env: str = "dev"
    commit: str = "local"
    api_base: str = "/api"

class KPI(BaseModel):
    label: str
    value: str

class TrendData(BaseModel):
    labels: List[str]
    values: List[float]

class DashboardMetrics(BaseModel):
    kpis: List[KPI]
    trend: TrendData

class Message(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    messages: List[Message]

class ChatResponse(BaseModel):
    reply: str

# ... (بقية نماذج البيانات والأمان كما هي)

# ============================================================================
# API Endpoints (نقاط النهاية)
# ============================================================================

@app.get("/api/version", response_model=ServiceInfo)
async def get_version():
    return ServiceInfo()

@app.get("/api/dashboard/metrics", response_model=DashboardMetrics)
async def get_dashboard_metrics():
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

# 3. تعديل نقطة نهاية الدردشة
@app.post("/api/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    # تحويل الرسائل إلى التنسيق المطلوب بواسطة OpenAI
    openai_messages = []
    for msg in request.messages:
        openai_messages.append({"role": msg.role, "content": msg.content})

    try:
        # استدعاء OpenAI API
        chat_completion = client.chat.completions.create(
            model="gemini-2.5-flash",  # يمكنك استخدام نماذج أخرى مثل gpt-4.1-mini
            messages=openai_messages
        )
        reply = chat_completion.choices[0].message.content
    except Exception as e:
        # في حال حدوث خطأ، يتم إرجاع رسالة خطأ واضحة
        raise HTTPException(status_code=500, detail=f"Error communicating with AI service: {str(e)}")

    return ChatResponse(reply=reply)

# ... (بقية نقاط النهاية مثل healthz و root كما هي)

@app.get("/")
async def root():
    return {"message": "Kristina Backend API is running. Visit /docs for API documentation."}

