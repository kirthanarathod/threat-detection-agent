"""
Agentic AI Threat Detection & Autonomous Response System
Main FastAPI server that receives security alerts and analyzes them using Llama 2
"""

from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
import requests
import json
from datetime import datetime
import logging
import os
from sqlalchemy.orm import Session

# Import database models
from .models import init_db, get_db, DecisionRecord

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Threat Detection Agent",
    description="Real-time security incident analysis powered by Llama 2",
    version="1.0.0"
)

# Ollama configuration (supports Docker environment variables)
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_API_URL = f"{OLLAMA_HOST}/api/generate"
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
    
    class Config:
        json_schema_extra = {
            "example": {
                "id": "alert_001",
                "source": "EDR",
                "event_type": "malware_detection",
                "description": "Ransomware signature detected",
                "severity": 0.95
            }
        }
    
    def validate_input(self):
        """Validate alert input"""
        errors = []
        
        if not self.id or len(self.id.strip()) == 0:
            errors.append("Alert ID cannot be empty")
        
        valid_sources = {"EDR", "Firewall", "IDS", "SIEM", "WAF", "CloudWatch", "Sentinel"}
        if self.source not in valid_sources:
            errors.append(f"Invalid source. Must be one of: {', '.join(valid_sources)}")
        
        if not self.event_type or len(self.event_type.strip()) == 0:
            errors.append("Event type cannot be empty")
        
        if not self.description or len(self.description.strip()) == 0:
            errors.append("Description cannot be empty")
        
        if not (0.0 <= self.severity <= 1.0):
            errors.append("Severity must be between 0.0 and 1.0")
        
        return errors
    
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
        
    Raises:
        Exception: If Ollama is unreachable or request fails
    """
    try:
        logger.info("Calling Ollama API...")
        response = requests.post(
            OLLAMA_API_URL,
            json={
                "model": MODEL_NAME,
                "prompt": prompt,
                "stream": False,
                "temperature": 0.7
            },
            timeout=120  # Increased timeout for first run
        )
        response.raise_for_status()
        return response.json()["response"]
    
    except requests.exceptions.ConnectionError as e:
        logger.error(f"❌ Cannot connect to Ollama at {OLLAMA_API_URL}. Is it running?")
        raise HTTPException(
            status_code=503,
            detail=f"Ollama service unavailable. Make sure Ollama is running (ollama serve)"
        )
    
    except requests.exceptions.Timeout:
        logger.error("Ollama API request timed out after 120 seconds")
        raise HTTPException(
            status_code=504,
            detail="Ollama API timed out. The model may be overloaded. Try again."
        )
    
    except requests.exceptions.HTTPError as e:
        logger.error(f"Ollama API error: {e.response.status_code} - {e.response.text}")
        raise HTTPException(
            status_code=502,
            detail=f"Ollama API error: {e.response.status_code}"
        )
    
    except KeyError:
        logger.error("Ollama response missing 'response' field")
        raise HTTPException(
            status_code=502,
            detail="Invalid response format from Ollama"
        )
    
    except Exception as e:
        logger.error(f"Unexpected error calling Ollama: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Unexpected error: {str(e)}"
        )

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
        "docs": "/docs",
        "database": "sqlite://threat_detection.db"
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
async def analyze_security_alert(alert: Alert, db: Session = Depends(get_db)) -> Decision:
    """
    Main endpoint: Analyze a security alert and save to database
    
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
        
        # Validate input
        validation_errors = alert.validate_input()
        if validation_errors:
            logger.warning(f"Alert validation failed: {validation_errors}")
            raise HTTPException(
                status_code=400,
                detail=f"Invalid alert data: {'; '.join(validation_errors)}"
            )
        
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
        
        # Save to database
        try:
            db_record = DecisionRecord(
                alert_id=alert.id,
                source=alert.source,
                event_type=alert.event_type,
                description=alert.description,
                alert_severity=alert.severity,
                threat_level=decision.threat_level,
                recommended_action=decision.recommended_action,
                confidence=decision.confidence,
                reasoning=decision.reasoning
            )
            db.add(db_record)
            db.commit()
            logger.info(f"✅ Decision saved to database: {alert.id}")
        except Exception as db_error:
            logger.error(f"Database error: {db_error}")
            db.rollback()
            raise HTTPException(
                status_code=500,
                detail=f"Failed to save decision to database: {str(db_error)}"
            )
        
        logger.info(f"Decision for {alert.id}: {decision.recommended_action} ({decision.threat_level})")
        return decision
        
    except HTTPException:
        # Re-raise HTTPExceptions (validation, Ollama, DB errors)
        raise
    
    except Exception as e:
        logger.error(f"Unexpected error analyzing alert {alert.id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Unexpected error: {str(e)}"
        )

@app.get("/decisions")
async def get_decisions(threat_level: str = None, limit: int = 50, db: Session = Depends(get_db)):
    """
    Query past decisions from database
    
    Optional filters:
    - threat_level: CRITICAL, HIGH, MEDIUM, LOW
    - limit: max number of results (default 50)
    """
    try:
        # Validate limit
        if limit < 1 or limit > 1000:
            raise HTTPException(
                status_code=400,
                detail="Limit must be between 1 and 1000"
            )
        
        # Validate threat_level if provided
        valid_threat_levels = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        if threat_level and threat_level.upper() not in valid_threat_levels:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid threat level. Must be one of: {', '.join(valid_threat_levels)}"
            )
        
        query = db.query(DecisionRecord).order_by(DecisionRecord.created_at.desc())
        
        if threat_level:
            query = query.filter(DecisionRecord.threat_level == threat_level.upper())
        
        decisions = query.limit(limit).all()
        
        return {
            "count": len(decisions),
            "decisions": [
                {
                    "alert_id": d.alert_id,
                    "threat_level": d.threat_level,
                    "recommended_action": d.recommended_action,
                    "confidence": d.confidence,
                    "created_at": d.created_at.isoformat()
                }
                for d in decisions
            ]
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error querying decisions: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Database error: {str(e)}"
        )

# ============================================================================
# STARTUP/SHUTDOWN
# ============================================================================

@app.on_event("startup")
async def startup():
    init_db()
    logger.info("🚀 Threat Detection Agent starting...")
    logger.info(f"📊 Using model: {MODEL_NAME}")
    logger.info(f"🔗 Ollama API: {OLLAMA_API_URL}")
    logger.info("💾 Database: SQLite (threat_detection.db)")

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
