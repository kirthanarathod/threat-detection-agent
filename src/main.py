"""
Agentic AI Threat Detection & Autonomous Response System
Main FastAPI server that receives security alerts and analyzes them using Llama 2
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests
import json
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Threat Detection Agent",
    description="Real-time security incident analysis powered by Llama 2",
    version="1.0.0"
)

# Ollama configuration
OLLAMA_API_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama2"

# ============================================================================
# DATA MODELS (Pydantic - validates incoming data)
# ============================================================================

class Alert(BaseModel):
    """Security alert data structure"""
    id: str
    source: str  # 'EDR', 'Firewall', 'IDS', etc.
    event_type: str  # e.g., 'privilege_escalation', 'lateral_movement'
    description: str
    severity: float  # 0.0 to 1.0
    
class Decision(BaseModel):
    """AI decision response"""
    alert_id: str
    threat_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    recommended_action: str  # block_ip, isolate_host, escalate, etc.
    confidence: float  # 0.0 to 1.0
    reasoning: str
    timestamp: str

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def call_llama2(prompt: str) -> str:
    """
    Call Ollama/Llama2 API to analyze security alert
    
    Args:
        prompt: The security analysis prompt
        
    Returns:
        LLM response text
    """
    try:
        response = requests.post(
            OLLAMA_API_URL,
            json={
                "model": MODEL_NAME,
                "prompt": prompt,
                "stream": False,
                "temperature": 0.7
            },
            timeout=30
        )
        response.raise_for_status()
        return response.json()["response"]
    except Exception as e:
        logger.error(f"Ollama API error: {e}")
        raise

def analyze_alert(alert: Alert) -> dict:
    """
    Analyze a security alert using Llama 2
    
    Args:
        alert: The security alert to analyze
        
    Returns:
        dict with threat_level, action, confidence, reasoning
    """
    
    # Create a prompt for Llama 2
    prompt = f"""You are a cybersecurity expert analyzing a security alert.

Alert Details:
- Source: {alert.source}
- Type: {alert.event_type}
- Description: {alert.description}
- Severity Score: {alert.severity}

Analyze this alert and respond in this exact JSON format (ONLY JSON, no other text):
{{
    "threat_level": "CRITICAL|HIGH|MEDIUM|LOW",
    "recommended_action": "block_ip|isolate_host|investigate|escalate|dismiss",
    "confidence": 0.0-1.0,
    "reasoning": "brief explanation"
}}

Think about:
1. Is this a real threat or false positive?
2. What's the risk level?
3. What action should be taken?
4. How confident are you?

Respond ONLY with valid JSON."""

    try:
        # Call Llama 2
        response_text = call_llama2(prompt)
        logger.info(f"Llama 2 response: {response_text[:200]}...")
        
        # Extract JSON from response
        response_json = json.loads(response_text)
        return response_json
    except json.JSONDecodeError:
        logger.error("Failed to parse Llama 2 response as JSON")
        # Fallback: return conservative decision
        return {
            "threat_level": "MEDIUM",
            "recommended_action": "investigate",
            "confidence": 0.5,
            "reasoning": "Unable to parse AI response, marking for manual review"
        }

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.get("/")
async def root():
    """Root endpoint - basic info"""
    return {
        "name": "Agentic AI Threat Detection & Autonomous Response System",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs"
    }

@app.get("/health")
async def health_check():
    """Health check - is the system running?"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "llm_model": MODEL_NAME
    }

@app.post("/analyze")
async def analyze_security_alert(alert: Alert) -> Decision:
    """
    Main endpoint: Analyze a security alert
    
    Example request:
    {
        "id": "alert_001",
        "source": "EDR",
        "event_type": "privilege_escalation",
        "description": "svchost.exe spawned cmd.exe with SYSTEM privileges",
        "severity": 0.85
    }
    """
    try:
        logger.info(f"Analyzing alert: {alert.id}")
        
        # Analyze using Llama 2
        analysis = analyze_alert(alert)
        
        # Create response
        decision = Decision(
            alert_id=alert.id,
            threat_level=analysis.get("threat_level", "UNKNOWN"),
            recommended_action=analysis.get("recommended_action", "escalate"),
            confidence=float(analysis.get("confidence", 0.5)),
            reasoning=analysis.get("reasoning", ""),
            timestamp=datetime.utcnow().isoformat()
        )
        
        logger.info(f"Decision for {alert.id}: {decision.recommended_action} ({decision.threat_level})")
        return decision
        
    except Exception as e:
        logger.error(f"Error analyzing alert: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# STARTUP/SHUTDOWN
# ============================================================================

@app.on_event("startup")
async def startup():
    logger.info("🚀 Threat Detection Agent starting...")
    logger.info(f"📊 Using model: {MODEL_NAME}")
    logger.info(f"🔗 Ollama API: {OLLAMA_API_URL}")

@app.on_event("shutdown")
async def shutdown():
    logger.info("⛔ Threat Detection Agent shutting down...")

# ============================================================================
# RUN
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    logger.info("Starting FastAPI server...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
