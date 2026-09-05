# 5-Minute Video Pitch Script: Vigil. Payment Risk Intelligence

This guide provides a structured, time-stamped script you can follow while recording your 5-minute demo video.

---

## ⏱️ Timeline & Presentation Flow

### 0:00 – 1:00 | The Problem & Vision
* **On Screen:** Start on the **Landing Page** (`/welcome` or clicking **Product Tour**).
* **What to say:**
  > *"Welcome everyone. High-scale payment platforms like Razorpay process millions of daily API transactions and webhook events. Security operations teams are flooded with thousands of raw alerts: failed auth bursts, unusual admin queries, and refund volume spikes.*
  > 
  > *This creates severe alert fatigue. Legitimate merchant activities—like end-of-month subscription cancellation batches—trigger false alarms, while sophisticated threats like distributed credential stuffing across merchant API keys or unauthorized settlement routing tampering get buried in raw logs.*
  > 
  > *We built **Vigil.** to solve this: an enterprise payment risk intelligence platform that pairs deterministic anomaly detection with an evidence-grounded AI copilot."*

---

### 1:00 – 2:30 | Incident Queue & Live Triage
* **On Screen:** Click **"Enter Live Operations Dashboard"** to enter the **Incident Queue**.
* **What to say:**
  > *"Here is the live Vigil operations workspace. In the top ribbon, you immediately see real-time KPIs across 1,284 gateway events, showing our 94.2% precision and 96.8% recall.*
  > 
  > *On the left is our prioritized incident queue. Let's look at **INC-001**: Distributed Credential Stuffing. When we select it, the right panel explains exactly what happened in plain English: two external IPs rotated through 14 different merchant keys in under 7 minutes with a 100% failure rate.*
  > 
  > *Notice that this is not a black-box AI prediction. The **Investigation Analysis** section breaks down the step-by-step reasoning chain, and every single claim is backed by cited raw telemetry event IDs (`evt_0019` to `evt_0035`)."*

---

### 2:30 – 3:30 | Interactive Remediation & False Positive Suppression
* **On Screen:** Click **"Apply Mitigation"** on `INC-001` -> Check the perimeter options -> Click **"Deploy Mitigations"**. Then click on `INC-004` (Routine Subscription Cancellation).
* **What to say:**
  > *"When an analyst decides to act, clicking **Apply Mitigation** allows them to immediately deploy perimeter WAF rules, force session key rotations, and notify merchants. Once deployed, the incident automatically closes, and the metrics ribbon updates live.*
  > 
  > *Now let's examine our false-positive handling on **INC-004**. Here, Merchant 088 issued 12 rapid refunds. While flagged by statistical volume rules, our copilot analyzed the payload metadata, recognized the uniform ₹499 plan amounts and recurring batch ID `BATCH-20260904-001`, and **correctly dismissed the alert with 99% confidence**, preventing unnecessary merchant payout freezes."*

---

### 3:30 – 4:30 | Gateway Telemetry & Log Inspector
* **On Screen:** Click **Gateway Telemetry** tab in the sidebar -> Click on row `evt_0001` to open the slide-over **Log Inspector Drawer**.
* **What to say:**
  > *"For deep forensic auditing, the **Gateway Telemetry** stream allows analysts to scroll through over 1,280 live transactions and filter by event ID, endpoint, or IP.*
  > 
  > *Clicking on any row instantly opens the **Log Inspector Drawer**, displaying formatted telemetry parameters, origin IP geolocation, and the raw JSON payload with HMAC signature headers."*

---

### 4:30 – 5:00 | Architecture & Conclusion
* **On Screen:** Click on **Model Benchmark** or **Team Administration** (`RA` user menu).
* **What to say:**
  > *"Under the hood, Vigil combines a deterministic rule engine for zero-hallucination detection, a resilient multi-tier LLM fallback chain (`gemini-2.5-flash`), and full role-based access administration.*
  > 
  > *Thank you for your time. Vigil transforms high-volume payment gateway noise into calibrated, explainable, and actionable security decisions."*
