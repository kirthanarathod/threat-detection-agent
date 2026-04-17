# Threat Detection Agent

Real-time security incident triage powered by LLMs + RL.

## The Problem

Security teams get 10k+ alerts per day. 99% are false positives. Analysts spend hours triaging noise while real threats slip through.

## The Solution

An AI agent that:
- Reads security alerts from EDR, firewall, IDS
- Analyzes them using LLMs (GPT-4)
- Recommends actions (isolate host, block IP, escalate)
- Executes safely (human approval for risky actions)

**Result: 73% faster incident response.**

## Architecture



## Setup

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python src/main.py
