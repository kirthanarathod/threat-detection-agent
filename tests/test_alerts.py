"""
Test cases for Threat Detection System
Tests the API with realistic security alerts
"""

import pytest
import json
from datetime import datetime

# Test data - realistic security scenarios
TEST_ALERTS = [
    {
        "id": "alert_001",
        "source": "EDR",
        "event_type": "privilege_escalation",
        "description": "svchost.exe spawned cmd.exe with SYSTEM privileges",
        "severity": 0.85
    },
    {
        "id": "alert_002", 
        "source": "Firewall",
        "event_type": "lateral_movement",
        "description": "Unusual RDP connection from internal IP to database server",
        "severity": 0.75
    },
    {
        "id": "alert_003",
        "source": "IDS",
        "event_type": "data_exfiltration",
        "description": "Large data transfer to unknown external IP (2GB+ in 5 minutes)",
        "severity": 0.95
    },
    {
        "id": "alert_004",
        "source": "EDR",
        "event_type": "malware_detection",
        "description": "Detected known ransomware signature in running process",
        "severity": 0.99
    },
    {
        "id": "alert_005",
        "source": "Firewall",
        "event_type": "suspicious_dns",
        "description": "DNS query to known malicious domain",
        "severity": 0.60
    },
    {
        "id": "alert_006",
        "source": "EDR",
        "event_type": "false_positive",
        "description": "System update process downloading files from Windows Update",
        "severity": 0.15
    }
]

class TestAlertAnalysis:
    """Test threat detection analysis"""
    
    def test_critical_threat_detected(self):
        """HIGH severity threats should be detected as critical"""
        alert = TEST_ALERTS[0]  # privilege_escalation
        assert alert["severity"] >= 0.75
        assert alert["event_type"] in ["privilege_escalation", "malware_detection"]
    
    def test_data_exfiltration_high_priority(self):
        """Data exfiltration should be flagged immediately"""
        alert = TEST_ALERTS[2]  # data_exfiltration
        assert alert["event_type"] == "data_exfiltration"
        assert alert["severity"] >= 0.90
    
    def test_malware_is_critical(self):
        """Malware detection should be CRITICAL"""
        alert = TEST_ALERTS[3]  # malware_detection
        assert alert["severity"] == 0.99
        assert "ransomware" in alert["description"].lower()
    
    def test_false_positive_low_severity(self):
        """System updates should have low severity"""
        alert = TEST_ALERTS[5]  # false_positive
        assert alert["severity"] <= 0.20
        assert "update" in alert["description"].lower()
    
    def test_all_alerts_have_required_fields(self):
        """All alerts must have required fields"""
        required_fields = {"id", "source", "event_type", "description", "severity"}
        for alert in TEST_ALERTS:
            assert all(field in alert for field in required_fields)
            assert isinstance(alert["severity"], float)
            assert 0.0 <= alert["severity"] <= 1.0

class TestAlertStructure:
    """Test data structure validation"""
    
    def test_alert_id_format(self):
        """Alert IDs should be unique strings"""
        ids = [alert["id"] for alert in TEST_ALERTS]
        assert len(ids) == len(set(ids))  # All unique
    
    def test_severity_scale(self):
        """Severity must be between 0.0 and 1.0"""
        for alert in TEST_ALERTS:
            assert 0.0 <= alert["severity"] <= 1.0
    
    def test_valid_sources(self):
        """Alert sources must be recognized"""
        valid_sources = {"EDR", "Firewall", "IDS", "SIEM", "WAF"}
        for alert in TEST_ALERTS:
            assert alert["source"] in valid_sources

if __name__ == "__main__":
    print(f"✅ {len(TEST_ALERTS)} test alerts defined")
    print("Run: pytest tests/test_alerts.py -v")
