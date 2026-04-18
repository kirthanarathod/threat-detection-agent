#!/bin/bash
cd /Users/kirthana/Desktop/threat-detection-agent
/opt/anaconda3/bin/python -m uvicorn src.main:app --host 0.0.0.0 --port 8000
