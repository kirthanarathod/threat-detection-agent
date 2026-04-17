"""
Configuration for Threat Detection Agent
"""
import os
from dotenv import load_dotenv

load_dotenv()

# API Configuration
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", 8000))

# LLM Configuration
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
LLM_MODEL = os.getenv("LLM_MODEL", "gpt-4")

# Database Configuration
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/threat_detection"
)

# Redis Configuration
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))

# Alert Processing
ALERT_BUFFER_SIZE = int(os.getenv("ALERT_BUFFER_SIZE", 10000))
ANOMALY_THRESHOLD = float(os.getenv("ANOMALY_THRESHOLD", 0.7))

print("Configuration loaded successfully")
