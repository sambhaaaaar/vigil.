# 🛡️ Vigil — AI-Powered Payment Risk Intelligence

> An enterprise risk triage and fraud intelligence platform designed for high-scale payment gateways.

Vigil is a two-stage risk intelligence pipeline and interactive review dashboard that monitors payment gateway events, identifies suspicious telemetry, and autonomously triages and audits threats — converting high-volume noise into calibrated, explainable security decisions.

## 🎯 The Problem

Risk and security teams at payment platforms face thousands of anomalous signals every day: credential stuffing attempts, abnormal refund bursts, and privileged configuration modifications. 

Most traditional systems flood analysts with raw alert volume. Legitimate merchant activities (such as scheduled subscription refund batches) trigger false alarms, while sophisticated low-and-slow credential stuffing or unauthorized settlement configuration tampering can go unnoticed.

**Vigil solves this.** It pairs precision rule-based anomaly detection with an evidence-grounded LLM triage copilot and an enterprise dashboard interface — delivering ranked incidents, explicit reasoning chains, and automated false-positive suppression.

## 🏗️ Architecture

```
Synthetic Razorpay logs (API calls / auth events / merchant activity)
        │
        ▼
┌─────────────────────────────────────────────┐
│  STAGE 1 — DETECTOR (Rule-Based)            │
│  • Credential stuffing (failed login rate)   │
│  • Admin anomaly (unusual endpoint + hours)  │
│  • Merchant refund spike (vs baseline)       │
│  → emits: {flag, rule_triggered, evidence}   │
└─────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────┐
│  STAGE 2 — TRIAGE COPILOT (LLM)            │
│  • Clusters related flags into incidents     │
│  • Decides severity (dismiss/watch/escalate) │
│  • Writes plain-English explanation          │
│  • Logs reasoning + confidence + audit trail │
│  → emits: {incident, severity, explanation}  │
└─────────────────────────────────────────────┘
        │
        ▼
   Ranked incident list + audit trail
   + one deliberately-shown failure case
```

## 🚀 Quick Start

### 1. Setup

```bash
# Clone and install
git clone <repo-url>
cd buildathon-project
pip install -r requirements.txt

# Configure LLM (copy and edit)
cp .env.example .env
# Add your API key to .env
```

### 2. Generate Synthetic Data

```bash
python data/generate_logs.py
# → Generates data/events.json (~250 events with seeded attack patterns)
```

### 3. Run the Full Pipeline

```bash
python -m pipeline.run
# → Detects anomalies, triages with LLM, outputs incidents + audit log
```

### 4. Evaluate Metrics

```bash
python -m pipeline.evaluate
# → Computes precision, recall, F1 against known ground truth
```

### 5. Launch Vigil Enterprise Dashboard

```bash
python ui/app.py
# → Runs dashboard on http://127.0.0.1:8000
```

## 📁 Project Structure

```
buildathon-project/
├── data/
│   ├── generate_logs.py      # Synthetic Razorpay event generator
│   └── events.json           # Generated dataset (285 events)
├── detector/
│   ├── __init__.py
│   └── rules.py              # Stage 1 — 3 detection rules
├── copilot/
│   ├── __init__.py
│   ├── prompts.py            # LLM prompt templates (evidence-forcing)
│   └── triage.py             # Stage 2 — LLM triage + audit
├── pipeline/
│   ├── __init__.py
│   ├── run.py                # End-to-end orchestrator
│   └── evaluate.py           # Metrics computation
├── ui/
│   └── app.py                # Enterprise dashboard server (FastAPI)
├── output/                   # Generated at runtime
│   ├── flags.json            # Detector flags
│   ├── incidents.json        # Triaged incidents
│   ├── audit_log.json        # Full audit trail
│   ├── evaluation.json       # Evaluation results
│   └── metrics.md            # Metrics table
├── requirements.txt
├── .env.example
└── README.md
```

## 🔍 Seeded Attack Patterns

| # | Pattern | What happens | Expected severity |
|---|---------|-------------|-------------------|
| 1 | **Credential Stuffing** | 35+ failed logins from 2 IPs across many API keys in 10 min | escalate |
| 2 | **Admin Anomaly** | admin_04 hits `/v1/settlements/config` at 3AM from VPN | escalate |
| 3 | **Merchant Refund Spike** | merchant_042 issues 18 refunds in 30 min (baseline: 2/day) | escalate |
| 4 | **False Positive** (deliberate) | merchant_088 runs legitimate bulk subscription refund batch | dismiss / watch |

The false positive (#4) is our "failure handled gracefully" — the copilot should recognize batch metadata, consistent amounts, and automation patterns to correctly avoid escalating.

## 🧠 Why This Design

### Stage 1: Rules, not ML
For a 1-day build, simple aggregation rules (sliding window counts, baseline ratios, endpoint history) are honest, explainable, and sufficient. ML would add complexity without adding value here.

### Stage 2: LLM as Analyst, not Oracle
The LLM doesn't make the detection decision — rules do that. The LLM reasons over the evidence, considers alternatives (including benign explanations), and produces a human-readable assessment with cited evidence and calibrated confidence. This makes it **explainable and audited**, not a black box.

### Prompt Design
The prompts force the model to:
- **Cite specific event IDs** when making claims
- **Consider false-positive explanations** before escalating
- **Output confidence scores** (0.0–1.0)
- **Log reasoning steps** explicitly

## 🔒 Defense-Only

This tool is strictly defense-oriented. It detects and explains threats — it does not generate attack payloads, exploit vulnerabilities, or provide offense capabilities.

## 📊 Evaluation Metrics

### Overall Performance

| Metric | Value |
|--------|-------|
| **Precision** | **100.0%** |
| **Recall** | **100.0%** |
| **F1 Score** | **100.0%** |
| True Positives | 3 |
| False Positives | 0 |
| False Negatives | 0 |

### Detection Results (Stage 1)

Detection recall: **3/3** attacks caught

| Attack Pattern | Detected | Event Recall |
|----------------|----------|--------------|
| Credential Stuffing | ✅ | 53% |
| Admin Anomaly | ✅ | 100% |
| Merchant Refund Spike | ✅ | 100% |

> **Note on 53% event recall for credential stuffing:** The detector uses a sliding window approach which captures the densest cluster of events rather than all 38 seeded attack events. All 38 events were from the same attack — the detector correctly identified the attack pattern, just not every individual event in the cluster. This is by design: the detector flags the anomaly, and the triage copilot receives the full evidence.

### Triage Results (Stage 2)

Triage accuracy: **3/3** — all real attacks correctly escalated

| Attack | Expected | Actual | Confidence |
|--------|----------|--------|------------|
| Credential Stuffing | escalate | ✅ escalate | 0.95 |
| Admin Anomaly | escalate | ✅ escalate | 0.98 |
| Merchant Refund Spike | escalate | ✅ escalate | 0.88 |

### False Positive Handling ✅

**Deliberate false positive** (merchant_088 bulk subscription refund): **Correctly dismissed**

- Copilot severity: `dismiss` 
- Copilot confidence: `0.99`
- The copilot correctly identified batch metadata (`BATCH-20260904-001`), consistent ₹499 amounts, `bulk_operation=true` flag, and automated processor tag as indicators of legitimate subscription cancellation batch processing.

### What We Got Wrong (Honest Assessment)

| Issue | Details |
|-------|---------|
| Credential stuffing event recall | 53% — detector's sliding window captures the attack but not every individual event. Acceptable since the triage copilot still receives all evidence. |
| Gemini API stability | Model availability varies; retry logic with model fallback was needed for reliable pipeline execution. |
| — | All seeded attack patterns correctly identified and triaged ✅ |

## ⚙️ LLM Providers Supported

| Provider | Model | Config |
|----------|-------|--------|
| Google Gemini | gemini-2.5-flash (with fallback chain) | `GEMINI_API_KEY` |
| OpenAI | gpt-4o-mini | `OPENAI_API_KEY` |
| Groq | llama-3.1-70b | `GROQ_API_KEY` |

Set `LLM_PROVIDER` in `.env` to switch between providers.

## 📝 License

Built for the Razorpay AI Buildathon 2026.
