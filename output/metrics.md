## 📊 Evaluation Metrics

### Overall Performance

| Metric | Value |
|--------|-------|
| Precision | 100.0% |
| Recall | 100.0% |
| F1 Score | 100.0% |
| True Positives | 3 |
| False Positives | 0 |
| False Negatives | 0 |

### Detection Results (Stage 1)

Detection recall: **3/3** attacks caught

| Attack Pattern | Detected | Event Recall |
|----------------|----------|--------------|
| credential_stuffing | ✅ | 53% |
| admin_anomaly | ✅ | 100% |
| merchant_refund_spike | ✅ | 100% |

### Triage Results (Stage 2)

Triage accuracy: **3/3**

| Attack | Expected | Actual | Correct | Confidence |
|--------|----------|--------|---------|------------|
| credential_stuffing | escalate | escalate | ✅ | 0.98 |
| admin_anomaly | escalate | escalate | ✅ | 0.98 |
| merchant_refund_spike | escalate | escalate | ✅ | 0.88 |

### False Positive Handling

**Deliberate false positive** (merchant_088 bulk refund): ✅ Correctly handled

- Copilot severity: `dismiss`
- Copilot confidence: `0.99`
- Explanation: *An automated detection rule flagged a spike in refunds for merchant_088; however...*

### What We Got Wrong (Honest Assessment)

| Issue | Details |
|-------|---------|
| — | All seeded patterns correctly identified and triaged ✅ |