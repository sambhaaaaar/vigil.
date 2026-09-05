"""
Stage 2 — LLM Triage Copilot

Takes flagged events from Stage 1 and produces triaged incidents
with severity, explanation, recommended actions, and full audit trail.

Supports multiple LLM providers: Gemini, OpenAI, Groq.
"""

import json
import hashlib
import os
import sys
import re
from datetime import datetime, timezone
from pathlib import Path

# Force UTF-8 output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from copilot.prompts import SYSTEM_PROMPT, CLUSTERING_PROMPT, TRIAGE_PROMPT


def get_llm_provider():
    """Detect which LLM provider is configured."""
    provider = os.environ.get("LLM_PROVIDER", "").lower()
    
    if provider == "openai" or os.environ.get("OPENAI_API_KEY"):
        return "openai"
    elif provider == "groq" or os.environ.get("GROQ_API_KEY"):
        return "groq"
    elif provider == "gemini" or os.environ.get("GEMINI_API_KEY"):
        return "gemini"
    else:
        return None


def call_gemini(prompt: str, system: str = SYSTEM_PROMPT) -> str:
    """Call Google Gemini API using the new google.genai SDK with retry logic."""
    import time as _time
    from google import genai
    from google.genai import types
    
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY environment variable not set")
    
    client = genai.Client(api_key=api_key)
    
    # Try models in order of preference
    models_to_try = ["gemini-2.5-flash", "gemini-flash-latest", "gemini-2.5-flash-lite", "gemini-3.5-flash-lite"]
    max_retries = 4
    
    last_error = None
    for model_name in models_to_try:
        for attempt in range(max_retries):
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=system,
                        temperature=0.2,
                        max_output_tokens=4096,
                        response_mime_type="application/json",
                        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
                    ),
                )
                return response.text
            except Exception as e:
                last_error = e
                err_str = str(e)
                if "404" in err_str or "not available" in err_str.lower():
                    break  # Skip to next model
                if "503" in err_str or "429" in err_str or "overloaded" in err_str.lower() or "high demand" in err_str.lower():
                    wait = (2 ** attempt) * 2  # 2s, 4s, 8s
                    print(f"    ... Gemini {model_name} busy, retrying in {wait}s (attempt {attempt+1}/{max_retries})")
                    _time.sleep(wait)
                    continue
                raise  # Re-raise unexpected errors
    
    raise last_error  # All models and retries exhausted


def call_openai(prompt: str, system: str = SYSTEM_PROMPT) -> str:
    """Call OpenAI API."""
    from openai import OpenAI
    
    client = OpenAI()
    response = client.chat.completions.create(
        model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
        max_tokens=4096,
        response_format={"type": "json_object"},
    )
    return response.choices[0].message.content


def call_groq(prompt: str, system: str = SYSTEM_PROMPT) -> str:
    """Call Groq API (fast inference for Llama/Mixtral)."""
    from openai import OpenAI
    
    client = OpenAI(
        api_key=os.environ.get("GROQ_API_KEY"),
        base_url="https://api.groq.com/openai/v1",
    )
    response = client.chat.completions.create(
        model=os.environ.get("GROQ_MODEL", "llama-3.1-70b-versatile"),
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
        max_tokens=4096,
        response_format={"type": "json_object"},
    )
    return response.choices[0].message.content


def call_llm(prompt: str, system: str = SYSTEM_PROMPT) -> str:
    """Route to the configured LLM provider."""
    provider = get_llm_provider()
    
    if provider == "gemini":
        return call_gemini(prompt, system)
    elif provider == "openai":
        return call_openai(prompt, system)
    elif provider == "groq":
        return call_groq(prompt, system)
    else:
        raise ValueError(
            "No LLM provider configured. Set one of: "
            "GEMINI_API_KEY, OPENAI_API_KEY, or GROQ_API_KEY in your .env file"
        )


def parse_llm_json(response_text: str) -> dict:
    """Parse JSON from LLM response, handling markdown code blocks."""
    text = response_text.strip()
    
    # Remove markdown code block markers if present
    if text.startswith("```"):
        # Remove opening ```json or ``` and closing ```
        text = re.sub(r'^```(?:json)?\s*\n?', '', text)
        text = re.sub(r'\n?```\s*$', '', text)
    
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        # Try to find JSON in the response
        json_match = re.search(r'\{[\s\S]*\}', text)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass
        raise ValueError(f"Failed to parse LLM response as JSON: {e}\nResponse: {text[:500]}")


def cluster_flags(flags: list[dict]) -> list[dict]:
    """
    Use LLM to cluster related flags into incidents.
    Falls back to rule-based clustering if LLM fails.
    """
    if not flags:
        return []

    # Try LLM-based clustering
    try:
        prompt = CLUSTERING_PROMPT.format(
            flags_json=json.dumps(flags, indent=2)
        )
        response = call_llm(prompt)
        result = parse_llm_json(response)
        return result.get("incidents", [])
    except Exception as e:
        print(f"  ⚠ LLM clustering failed ({e}), using rule-based fallback")
        return _fallback_cluster(flags)


def _fallback_cluster(flags: list[dict]) -> list[dict]:
    """Rule-based fallback clustering: group by rule type."""
    clusters = {}
    for flag in flags:
        rule = flag["rule"]
        if rule not in clusters:
            clusters[rule] = {
                "incident_group": rule.lower().replace("_", "-"),
                "related_flag_ids": [],
                "reasoning": f"Grouped by detection rule: {rule}",
            }
        clusters[rule]["related_flag_ids"].append(flag["flag_id"])
    return list(clusters.values())


def get_events_for_flags(flags: list[dict], all_events: list[dict]) -> list[dict]:
    """Extract the raw events referenced by a set of flags."""
    event_ids = set()
    for flag in flags:
        event_ids.update(flag.get("events", []))
    
    return [e for e in all_events if e["event_id"] in event_ids]


def triage_incident(
    incident_group: dict,
    flags: list[dict],
    all_events: list[dict],
    incident_number: int,
) -> dict:
    """
    Triage a single incident using the LLM.
    
    Returns a structured incident assessment with severity, explanation,
    and full audit trail.
    """
    incident_id = f"INC-{str(incident_number).zfill(3)}"
    
    # Get the flags for this incident
    flag_ids = incident_group["related_flag_ids"]
    incident_flags = [f for f in flags if f["flag_id"] in flag_ids]
    
    # Get the raw events referenced by these flags
    relevant_events = get_events_for_flags(incident_flags, all_events)
    
    # Build the triage prompt
    prompt = TRIAGE_PROMPT.format(
        flags_json=json.dumps(incident_flags, indent=2),
        events_json=json.dumps(relevant_events, indent=2),
        incident_id=incident_id,
        flag_ids=json.dumps(flag_ids),
    )
    
    prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:12]
    
    try:
        response = call_llm(prompt)
        result = parse_llm_json(response)
        
        # Ensure required fields exist
        result.setdefault("incident_id", incident_id)
        result.setdefault("related_flags", flag_ids)
        result.setdefault("severity", "watch")
        result.setdefault("confidence", 0.5)
        result.setdefault("explanation", "Analysis completed but explanation missing")
        result.setdefault("recommended_action", "Manual review required")
        
        # Add audit metadata
        if "audit" not in result:
            result["audit"] = {}
        result["audit"]["model"] = _get_model_name()
        result["audit"]["prompt_hash"] = prompt_hash
        result["audit"]["timestamp"] = datetime.now(timezone.utc).isoformat()
        result["audit"]["llm_provider"] = get_llm_provider()
        
        return result
        
    except Exception as e:
        # Return a fallback triage if LLM fails
        return {
            "incident_id": incident_id,
            "title": f"Auto-flagged: {incident_group.get('incident_group', 'unknown')}",
            "related_flags": flag_ids,
            "severity": "watch",
            "confidence": 0.3,
            "explanation": f"LLM triage failed ({e}). Manual review recommended based on rule-based detection.",
            "recommended_action": "Escalate to senior analyst for manual review",
            "attack_category": "unknown",
            "audit": {
                "model": "fallback",
                "prompt_hash": prompt_hash,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "error": str(e),
                "reasoning_steps": ["LLM call failed", "Falling back to conservative 'watch' severity"],
                "evidence_used": [e["event_id"] for e in relevant_events[:5]],
            },
        }


def _get_model_name() -> str:
    """Get the model name for audit logging."""
    provider = get_llm_provider()
    if provider == "gemini":
        return "gemini-2.5-flash"
    elif provider == "openai":
        return os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    elif provider == "groq":
        return os.environ.get("GROQ_MODEL", "llama-3.1-70b-versatile")
    return "unknown"


def run_triage(flags: list[dict], all_events: list[dict]) -> list[dict]:
    """
    Full triage pipeline:
    1. Cluster related flags into incidents
    2. Triage each incident with the LLM
    3. Return sorted incidents (escalate first)
    """
    print("\n  Clustering related flags into incidents...")
    incident_groups = cluster_flags(flags)
    print(f"     Found {len(incident_groups)} incident group(s)")
    
    incidents = []
    for i, group in enumerate(incident_groups, 1):
        print(f"\n  Triaging incident {i}/{len(incident_groups)}: {group.get('incident_group', 'unknown')}...")
        incident = triage_incident(group, flags, all_events, i)
        incidents.append(incident)
        print(f"     -> {incident.get('severity', '?').upper()} (confidence: {incident.get('confidence', '?')})")
    
    # Sort: escalate > watch > dismiss
    severity_order = {"escalate": 0, "watch": 1, "dismiss": 2}
    incidents.sort(key=lambda x: severity_order.get(x.get("severity", "watch"), 1))
    
    return incidents


def main():
    """Standalone test: load flags from detector and run triage."""
    from dotenv import load_dotenv
    load_dotenv()
    
    events_path = Path(__file__).parent.parent / "data" / "events.json"
    with open(events_path) as f:
        events = json.load(f)
    
    # Run detector first
    from detector.rules import run_all_rules
    flags = run_all_rules(events)
    
    print(f"Loaded {len(events)} events, {len(flags)} flags")
    
    # Run triage
    incidents = run_triage(flags, events)
    
    print(f"\n{'='*60}")
    print(f" Triage Results — {len(incidents)} incidents")
    print(f"{'='*60}")
    for inc in incidents:
        print(f"\n  [{inc.get('severity', '?').upper():>8}] {inc.get('incident_id')} — {inc.get('title', 'N/A')}")
        print(f"           Confidence: {inc.get('confidence', '?')}")
        print(f"           {inc.get('explanation', 'N/A')[:100]}...")


if __name__ == "__main__":
    main()
