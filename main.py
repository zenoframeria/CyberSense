# ============================================
# main.py — FastAPI Server for CyberSense
# ============================================

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
# pydantic = validates incoming data format automatically

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

# allow Frontend to call this API from any origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # allow all origins for hackathon
    allow_methods=["*"],   # allow GET, POST, etc.
    allow_headers=["*"],
)


# define input format for each endpoint
class SMSRequest(BaseModel):
    # Frontend must send us
    text: str      # SMS text
    sender: str = ""  # sender name (optional)

class URLRequest(BaseModel):
    url: str       # URL to scan

# ============================================
# ENDPOINT 1: SMS Analyzer
# ============================================

@app.post("/analyze/sms")
def analyze_sms_endpoint(request: SMSRequest):
    # receive SMS from Frontend → analyze → return result
    result = analyze_sms(request.text, request.sender)
    return result

# ============================================
# ENDPOINT 2: URL Scanner
# ============================================

@app.post("/analyze/url")
def analyze_url_endpoint(request: URLRequest):
    # receive URL from Frontend → scan → return result
    result = scan_url(request.url)
    return result

# ============================================
# ENDPOINT 3: Check if the server is still running. (Health Check)
# ============================================

@app.get("/")
def health_check():
    return {"status": "CyberSense API is running!"}

# ============================================
# run server
# ============================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)