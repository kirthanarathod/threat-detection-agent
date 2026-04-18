const API_BASE = window.location.origin;

// DOM Elements
const alertForm = document.getElementById('alertForm');
const resultSection = document.getElementById('resultSection');
const resultCard = document.getElementById('resultCard');
const errorMsg = document.getElementById('errorMsg');
const decisionsList = document.getElementById('decisionsList');
const threatFilter = document.getElementById('threatFilter');
const severityInput = document.getElementById('severity');
const severityValue = document.getElementById('severityValue');

// Update severity value display
if (severityInput && severityValue) {
    severityInput.addEventListener('input', (e) => {
        severityValue.textContent = parseFloat(e.target.value).toFixed(2);
    });
}

// Form submission
alertForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    await analyzeAlert();
});

// Threat filter change
threatFilter.addEventListener('change', () => {
    loadDecisions();
});

async function analyzeAlert() {
    const alertId = document.getElementById('alertId').value;
    const source = document.getElementById('source').value;
    const eventType = document.getElementById('eventType').value;
    const severity = parseFloat(document.getElementById('severity').value);
    const description = document.getElementById('description').value;

    // Validate
    if (!alertId || !source || !eventType || !description || isNaN(severity)) {
        showError('Please fill in all fields');
        return;
    }

    if (severity < 0 || severity > 1) {
        showError('Severity must be between 0 and 1');
        return;
    }

    // Show loading state
    const submitBtn = alertForm.querySelector('button');
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="spinner"></span> Analyzing...';

    try {
        const response = await fetch(`${API_BASE}/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                id: alertId,
                source: source,
                event_type: eventType,
                description: description,
                severity: severity,
            }),
        });

        const data = await response.json();

        if (!response.ok) {
            showError(data.detail || 'Error analyzing alert');
            return;
        }

        // Display result
        displayResult(data);
        
        // Clear form
        alertForm.reset();
        
        // Reload decisions
        setTimeout(() => loadDecisions(), 500);

    } catch (error) {
        showError(`Error: ${error.message}`);
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '🔍 Analyze Alert';
    }
}

function displayResult(data) {
    const threatClass = `threat-${data.threat_level.toLowerCase()}`;
    resultCard.innerHTML = `
        <div class="result-item">
            <div class="result-label">Alert ID</div>
            <div class="result-value">${data.alert_id}</div>
        </div>
        <div class="result-item">
            <div class="result-label">Threat Level</div>
            <span class="threat-badge ${threatClass}">${data.threat_level}</span>
        </div>
        <div class="result-item">
            <div class="result-label">Action</div>
            <div class="result-value" style="font-size: 1.1rem;">${formatAction(data.recommended_action)}</div>
        </div>
        <div class="result-item">
            <div class="result-label">Confidence</div>
            <div class="result-value">${(data.confidence * 100).toFixed(0)}%</div>
        </div>
        <div class="result-reasoning">
            <div class="result-reasoning-label">AI Reasoning</div>
            <div class="result-reasoning-text">${data.reasoning}</div>
        </div>
    `;
    resultSection.style.display = 'block';
    resultSection.scrollIntoView({ behavior: 'smooth' });
}

async function loadDecisions() {
    const threatLevel = threatFilter.value;
    
    try {
        const url = threatLevel 
            ? `${API_BASE}/decisions?threat_level=${threatLevel}&limit=20`
            : `${API_BASE}/decisions?limit=20`;
        
        const response = await fetch(url);
        const data = await response.json();

        if (!response.ok) {
            showError('Error loading decisions');
            return;
        }

        displayDecisions(data.decisions || []);
        updateStats(data.decisions || []);

    } catch (error) {
        showError(`Error: ${error.message}`);
    }
}

function displayDecisions(decisions) {
    if (decisions.length === 0) {
        decisionsList.innerHTML = '<div style="text-align: center; color: var(--text-muted); padding: 40px 20px;">No decisions yet</div>';
        return;
    }

    decisionsList.innerHTML = decisions.map(d => {
        const threatClass = `threat-${d.threat_level.toLowerCase()}`;
        const time = new Date(d.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const confidence = (d.confidence * 100).toFixed(0);
        return `
            <div class="decision-item">
                <div class="decision-id">${d.alert_id}</div>
                <div class="decision-time">${time}</div>
                <div class="decision-threat">
                    <span class="threat-badge ${threatClass}">${d.threat_level}</span>
                </div>
                <div class="decision-action">${formatAction(d.recommended_action)}</div>
                <div class="decision-confidence">
                    🎯 ${confidence}% Confidence
                    <div class="confidence-bar">
                        <div class="confidence-fill" style="width: ${confidence}%"></div>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function updateStats(decisions) {
    document.getElementById('totalAlerts').textContent = decisions.length;
    document.getElementById('criticalCount').textContent = decisions.filter(d => d.threat_level === 'CRITICAL').length;
    document.getElementById('highCount').textContent = decisions.filter(d => d.threat_level === 'HIGH').length;
    document.getElementById('mediumCount').textContent = decisions.filter(d => d.threat_level === 'MEDIUM').length;
}

function formatAction(action) {
    const actions = {
        'isolate_host': '🔒 Isolate Host',
        'block_ip': '🚫 Block IP',
        'investigate': '🔍 Investigate',
        'escalate': '⚠️ Escalate',
        'dismiss': '✅ Dismiss',
    };
    return actions[action] || action;
}

function showError(message) {
    errorMsg.textContent = message;
    errorMsg.style.display = 'block';
    
    setTimeout(() => {
        errorMsg.style.display = 'none';
    }, 5000);
}

// Load decisions on page load
document.addEventListener('DOMContentLoaded', () => {
    loadDecisions();
});
