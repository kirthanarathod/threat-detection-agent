"""
Database models for Threat Detection System
Uses SQLAlchemy ORM to store decisions
"""

from sqlalchemy import Column, String, Float, DateTime, Integer, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

# SQLite database file
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./threat_detection.db")

# Create engine
engine = create_engine(
    DATABASE_URL, 
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

# Session maker
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()

# ============================================================================
# DATABASE MODELS
# ============================================================================

class DecisionRecord(Base):
    """Store decisions made by the threat detection system"""
    
    __tablename__ = "decisions"
    
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String, unique=True, index=True)
    source = Column(String)  # EDR, Firewall, IDS, etc.
    event_type = Column(String)  # privilege_escalation, malware, etc.
    description = Column(String)
    alert_severity = Column(Float)  # Original alert severity (0-1)
    threat_level = Column(String)  # CRITICAL, HIGH, MEDIUM, LOW
    recommended_action = Column(String)  # block_ip, isolate_host, etc.
    confidence = Column(Float)  # Model confidence (0-1)
    reasoning = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f"<Decision {self.alert_id}: {self.threat_level}>"

# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

def init_db():
    """Create all database tables"""
    Base.metadata.create_all(bind=engine)
    print("✅ Database initialized")

def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

if __name__ == "__main__":
    init_db()
