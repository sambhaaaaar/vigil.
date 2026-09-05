"""
Stage 2 — LLM Prompt Templates for Triage Copilot

Designed to force the model to:
  - Cite specific event IDs as evidence
  - Output structured JSON with confidence scores  
  - Explain reasoning in plain English
  - Handle false positives gracefully
"""

SYSTEM_PROMPT = """You are an expert Security Operations Center (SOC) analyst working for Razorpay, 
India's largest payment infrastructure company. You protect payment APIs, merchant accounts, 
and admin systems from threats including credential stuffing, account takeover, insider threats, 
and transaction fraud.

Your role is to triage security alerts from an automated detection system. You receive 
structured flag data with raw evidence and must produce actionable incident assessments.

CRITICAL RULES:
1. Always cite specific event_ids from the evidence when making claims.
2. Always provide a confidence score (0.0 to 1.0) reflecting your certainty.
3. Consider whether flagged activity could be LEGITIMATE (bulk operations, batch processing, 
   scheduled maintenance) before escalating.
4. Your explanations must be clear enough for a human analyst with no additional context.
5. Log your reasoning steps explicitly — this is an audited system.
6. For payment-related flags, always consider financial impact and urgency."""


CLUSTERING_PROMPT = """Analyze the following security flags from Razorpay's detection system.
Group related flags into distinct incidents. Flags are related if they:
- Share the same actor_id or IP address
- Occur in the same time window (within 30 minutes)
- Represent different aspects of the same attack pattern

FLAGS:
{flags_json}

Respond with ONLY valid JSON in this exact format:
{{
  "incidents": [
    {{
      "incident_group": "descriptive-name",
      "related_flag_ids": ["FLG-001", "FLG-002"],
      "reasoning": "Why these flags are related"
    }}
  ]
}}"""


TRIAGE_PROMPT = """You are triaging a security incident on Razorpay's payment platform.

INCIDENT FLAGS:
{flags_json}

RAW EVENT EVIDENCE (the actual log entries that triggered these flags):
{events_json}

Analyze this incident and respond with ONLY valid JSON in this exact format:
{{
  "incident_id": "{incident_id}",
  "title": "Brief descriptive title (e.g., 'Credential Stuffing Attack on Payment API Auth')",
  "related_flags": {flag_ids},
  "severity": "escalate | watch | dismiss",
  "confidence": 0.0-1.0,
  "explanation": "A 2-4 sentence plain-English explanation that a human SOC analyst could trust. Include what happened, why it matters, and what evidence supports your conclusion.",
  "recommended_action": "Specific, actionable recommendation (e.g., 'Rate-limit IP 45.33.32.156, force password rotation for affected API keys, review access logs for lateral movement')",
  "financial_impact": "Estimated impact on Razorpay or merchants (e.g., 'Potential unauthorized access to payment APIs affecting N merchants')",
  "attack_category": "credential_stuffing | insider_threat | transaction_fraud | account_takeover | benign_activity | other",
  "mitre_tactic": "Best matching MITRE ATT&CK tactic if applicable, else 'N/A'",
  "audit": {{
    "reasoning_steps": [
      "Step 1: description of first reasoning step",
      "Step 2: description of second reasoning step",
      "Step 3: etc."
    ],
    "evidence_used": ["evt_0001", "evt_0002"],
    "evidence_not_used": ["evt_ids that were provided but not relevant"],
    "alternative_explanations_considered": [
      "Could this be a legitimate bulk operation? Why/why not."
    ],
    "confidence_factors": {{
      "supporting": ["factor raising confidence"],
      "undermining": ["factor lowering confidence"]
    }}
  }}
}}

IMPORTANT GUIDANCE:
- severity="escalate": Clear attack requiring immediate action. High confidence, real threat.
- severity="watch": Suspicious but not certain. Could be legitimate. Monitor but don't block.
- severity="dismiss": Likely benign activity that triggered a false positive. Explain why.

For REFUND-related flags, specifically check:
- Is there a batch_id or bulk_operation=true in metadata? → Likely legitimate batch processing.
- Are amounts consistent (same amount every time)? → Likely automated subscription refund.
- Is the IP consistent with the merchant's normal activity? → Less likely to be fraudulent.
- Are refund reasons varied vs uniform? → Uniform reasons suggest batch, varied suggest fraud.

Be honest about uncertainty. A well-calibrated "watch" with 0.6 confidence is better than a 
false "escalate" with 0.95."""


BATCH_TRIAGE_PROMPT = """You are an expert SOC analyst at Razorpay. Triage ALL of the following 
security incidents in a single response. For each incident, provide a complete assessment.

INCIDENTS TO TRIAGE:
{incidents_json}

Respond with ONLY valid JSON:
{{
  "triaged_incidents": [
    ... (one triage object per incident, same format as single triage)
  ]
}}"""
