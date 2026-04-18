const API_BASE = window.location.origin;

// DOM Elements
const alertForm = document.getElementById('alertForm');
const resultSection = document.getElementById('resultSection');
const resultCard = document.getElementById('resultCard');
const errorMsg = document.getElementById('errorMsg');
const decisionsList = document.getElementById('decisionsList');
const threatFilter = document.getElementById('threatFilter');

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
    const threatLevelClass = `threat-${data.threat_level.toLowerCase()}`;
    
    resultCard.innerHTML = `
        <div class="result-field">
            <strong>Alert ID:</strong>
            <span>${data.alert_id}</span>
        </div>
        <div class="result-field">
            <strong>Threat Level:</strong>
            <span class="threat-level ${threatLevelClass}">${data.threat_level}</span>
        </div>
        <div class="result-field">
            <strong>Recommended Action:</strong>
            <span>${formatAction(data.recommended_action)}</span>
        </div>
        <div class="result-field">
            <strong>Confidence:</strong>
            <span>${(data.confidence * 100).toFixed(0)}%</span>
        </div>
        <div class="result-field">
            <strong>Reasoning:</strong>
            <span>${data.reasoning}</span>
        </div>
        <div class="result-field">
            <strong>Timestamp:</strong>
            <span>${new Date(data.timestamp).toLocaleString()}</span>
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

    } catch (error) {
        showError(`Error: ${error.message}`);
    }
}

function displayDecisions(decisions) {
    if (decisions.length === 0) {
        decisionsList.innerHTML = '<p style="color: #999; text-align: center;">No decisions found</p>';
        return;
    }

    decisionsList.innerHTML = decisions.map(d => {
        const threatLevelClass = `threat-${d.threat_level.toLowerCase()}`;
        const createdAt = new Date(d.created_at).toLocaleString();
        
        return `
            <div class="decision-card">
                <div class="decision-header">
                    <div>
                        <span class="decision-id">${d.alert_id}</span>
                        <span class="threat-level ${threatLevelClass}">${d.threat_level}</span>
                    </div>
                    <span class="decision-timestamp">${createdAt}</span>
                </div>
                <div class="decision-action">
                    <strong>Action:</strong> ${formatAction(d.recommended_action)}
                </div>
                <div class="decision-confidence">
                    <strong>Confidence:</strong> ${(d.confidence * 100).toFixed(0)}%
                </div>
            </div>
        `;
    }).join('');
}

function formatAction(action) {
    const actions = {
        'isolate_host': '🔒 Isolate Host',
        'block_ip': '🚫 Block IP',
        'investigate': '🔍 Investigate',
        'escalate': '⚠️ Escalate',
        'dismiss': '✓ Dismiss',
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
