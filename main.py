# ============================================
# main.py — FastAPI Server for CyberSense
# ============================================

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import logging
from fastapi.staticfiles import StaticFiles

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), "02_ai"))

from sms_analyzer import analyze_sms
from url_scanner import scan_url


# create FastAPI app
app = FastAPI(
    title="CyberSense API",
    description="AI-powered Thai SMS & URL scam detection"
)

# allowed origins — add production domain here when deploying
ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:8080",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)


# define input format for each endpoint
class SMSRequest(BaseModel):
    text: str = Field(..., min_length=1)
    sender: str = ""

class URLRequest(BaseModel):
    url: str = Field(..., min_length=1)

# ============================================
# ENDPOINT 1: SMS Analyzer
# ============================================

@app.post("/analyze/sms")
def analyze_sms_endpoint(request: SMSRequest):
    try:
        result = analyze_sms(request.text, request.sender)
        return result
    except Exception as e:
        logging.error("analyze_sms failed: %s", e, exc_info=True)
        return {"error": True, "message": "SMS analysis failed. Please try again."}

# ============================================
# ENDPOINT 2: URL Scanner
# ============================================

@app.post("/analyze/url")
def analyze_url_endpoint(request: URLRequest):
    try:
        result = scan_url(request.url)
        return result
    except Exception as e:
        logging.error("scan_url failed: %s", e, exc_info=True)
        return {"error": True, "message": "URL scan failed. Please try again."}

# ============================================
# ENDPOINT 3: Check if the server is still running. (Health Check)
# ============================================

@app.get("/health")
def health_check():
    return {"status": "CyberSense API is running!"}

app.mount("/", StaticFiles(directory="01_frontend", html=True), name="static")
# ============================================
# run server
# ============================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

