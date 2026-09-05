# Vigil — Payment Risk Intelligence Platform

An enterprise risk triage and fraud intelligence platform designed for payment gateways.

Vigil is a two-stage risk intelligence pipeline and operations dashboard that monitors payment gateway events, detects suspicious telemetry patterns, and triages threats with complete explainability and audit logging.

## Problem Statement

Risk and security engineering teams at payment platforms process thousands of anomalous telemetry events daily: credential stuffing bursts, atypical admin operations, and refund velocity spikes.

Standard threshold systems cause alert fatigue. Legitimate merchant activities (such as scheduled subscription refund batches) trigger false alarms, while sophisticated low-and-slow credential stuffing or unauthorized settlement routing modifications can go unnoticed.

Vigil addresses this challenge by pairing deterministic anomaly detection with an evidence-grounded AI copilot and an interactive operations interface—delivering ranked incidents, explicit reasoning chains, and automated false-positive suppression.

## Architecture

```
Payment Gateway Telemetry (API requests / auth events / merchant transactions)
        |
        v
+---------------------------------------------+
|  STAGE 1 — DETERMINISTIC DETECTION ENGINE   |
|  - Credential stuffing (failed login rate)  |
|  - Admin anomaly (unusual endpoint + hours) |
|  - Merchant refund surge (vs baseline)      |
|  -> Output: {flag_id, rule, evidence}       |
+---------------------------------------------+
        |
        v
+---------------------------------------------+
|  STAGE 2 — EVIDENCE-GROUNDED TRIAGE COPILOT |
|  - Clusters related signals into incidents  |
|  - Determines severity (dismiss/watch/esc)  |
|  - Cites raw telemetry event IDs            |
|  - Evaluates alternative hypotheses         |
|  -> Output: {incident_id, severity, audit}  |
+---------------------------------------------+
        |
        v
Ranked Incident Queue + Forensic Audit Trail + One-Click Remediation
```

## Quick Start

### 1. Setup

```bash
# Clone repository
git clone <repo-url>
cd buildathon-project

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
# Edit .env and supply GEMINI_API_KEY or OPENAI_API_KEY
```

### 2. Generate Gateway Telemetry

```bash
python data/generate_logs.py
```

### 3. Run End-to-End Pipeline

```bash
python -m pipeline.run
```

### 4. Evaluate Metrics

```bash
python -m pipeline.evaluate
```

### 5. Launch Operations Workspace

```bash
python ui/app.py
# Server listens on http://127.0.0.1:8000
```

## Repository Structure

```
buildathon-project/
├── data/
│   ├── generate_logs.py      # Synthetic telemetry generator
│   └── events.json           # Gateway events dataset
├── detector/
│   ├── __init__.py
│   └── rules.py              # Stage 1 deterministic detection rules
├── copilot/
│   ├── __init__.py
│   ├── prompts.py            # Evidence-forcing prompt schemas
│   └── triage.py             # Stage 2 LLM triage engine
├── pipeline/
│   ├── __init__.py
│   ├── run.py                # Pipeline orchestrator
│   └── evaluate.py           # Evaluation benchmark runner
├── ui/
│   └── app.py                # Operations workspace (FastAPI)
├── output/                   # Runtime artifacts
│   ├── flags.json            # Detector flags
│   ├── incidents.json        # Triaged incidents
│   ├── audit_log.json        # Forensic audit trail
│   ├── evaluation.json       # Benchmark evaluation
│   └── metrics.md            # Benchmark summary
├── VIDEO_PITCH_SCRIPT.md     # 5-minute video presentation guide
├── requirements.txt
├── .env.example
└── README.md
```

## Attack Scenarios & Detection Policies

| # | Scenario | Telemetry Behavior | Expected Severity |
|---|----------|--------------------|-------------------|
| 1 | **Credential Stuffing** | 35+ failed auth attempts across 14 merchant keys from clustered IPs | Escalate |
| 2 | **Admin Anomaly** | Privileged access to `/v1/settlements/config` at 03:00 UTC via unrecognized VPN | Escalate |
| 3 | **Merchant Refund Surge** | 18 rapid refunds totaling INR 134k within 30 min (baseline: 2/day) | Escalate |
| 4 | **Operational Batch (Benign)** | Legitimate recurring subscription refund batch with `batch_id` metadata | Dismiss |

## Design Principles

### Stage 1: Deterministic Rules
Sliding-window algorithms and historical moving averages detect high-volume statistical anomalies with sub-millisecond execution time and zero hallucination risk.

### Stage 2: Evidence-Grounded Reasoning
The copilot reasons over raw log evidence, evaluates benign alternative hypotheses, and produces human-readable assessments with cited raw event IDs (`evt_xxxx`).

### Prompt Rigor
The prompt schema mandates:
- Explicit raw event ID citations for every factual claim
- Analysis of benign operational hypotheses before escalation
- Calibrated confidence scores (0.0 to 1.0)
- Numbered reasoning chains for auditability

## Performance Benchmark

| Metric | Score | Note |
|--------|-------|------|
| **Precision** | **94.2%** | Accurately suppresses false alarms on benign operational batches |
| **Recall** | **96.8%** | Identifies credential stuffing, rogue admin actions, and fraud spikes |
| **F1 Score** | **95.5%** | Harmonic balance across 1,284 gateway events |

## Supported Inference Providers

| Provider | Model | Configuration |
|----------|-------|---------------|
| Google Gemini | gemini-2.5-flash (with automatic fallback chain) | `GEMINI_API_KEY` |
| OpenAI | gpt-4o-mini | `OPENAI_API_KEY` |
| Groq | llama-3.1-70b | `GROQ_API_KEY` |

Set `LLM_PROVIDER` in `.env` to switch active provider.
