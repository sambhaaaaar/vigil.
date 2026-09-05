"""
Pipeline Orchestrator — run.py

End-to-end: Load events → Detect → Triage → Output
"""

import json
import sys
import os
import time
from datetime import datetime, timezone
from pathlib import Path

# Force UTF-8 output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def load_events():
    """Load synthetic events from data/events.json."""
    events_path = PROJECT_ROOT / "data" / "events.json"
    if not events_path.exists():
        print("  ⚠ events.json not found. Generating...")
        from data.generate_logs import generate_all
        events = generate_all()
        events_path.parent.mkdir(parents=True, exist_ok=True)
        with open(events_path, "w") as f:
            json.dump(events, f, indent=2)
        print(f"  ✓ Generated {len(events)} events → {events_path}")
    else:
        with open(events_path) as f:
            events = json.load(f)
        print(f"  ✓ Loaded {len(events)} events from {events_path}")
    return events


def run_detector(events):
    """Run Stage 1 rule-based detector."""
    from detector.rules import run_all_rules
    flags = run_all_rules(events)
    return flags


def run_copilot(flags, events):
    """Run Stage 2 LLM triage copilot."""
    from copilot.triage import run_triage
    incidents = run_triage(flags, events)
    return incidents


def save_outputs(flags, incidents, events):
    """Save pipeline outputs to output/ directory."""
    output_dir = PROJECT_ROOT / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save flags (detector output)
    flags_path = output_dir / "flags.json"
    with open(flags_path, "w") as f:
        json.dump(flags, f, indent=2)
    print(f"  ✓ Flags saved → {flags_path}")

    # Save incidents
    incidents_path = output_dir / "incidents.json"
    with open(incidents_path, "w") as f:
        json.dump(incidents, f, indent=2)
    print(f"  ✓ Incidents saved → {incidents_path}")

    # Build audit log
    audit_log = {
        "pipeline_run": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_events_processed": len(events),
            "flags_raised": len(flags),
            "incidents_created": len(incidents),
            "severity_breakdown": {},
        },
        "detector_audit": {
            "rules_executed": [
                "CREDENTIAL_STUFFING",
                "ADMIN_ANOMALY",
                "MERCHANT_REFUND_SPIKE",
            ],
            "flags": flags,
        },
        "triage_audit": {
            "incidents": [
                {
                    "incident_id": inc.get("incident_id"),
                    "severity": inc.get("severity"),
                    "confidence": inc.get("confidence"),
                    "audit": inc.get("audit", {}),
                }
                for inc in incidents
            ],
        },
    }

    # Compute severity breakdown
    for inc in incidents:
        sev = inc.get("severity", "unknown")
        audit_log["pipeline_run"]["severity_breakdown"][sev] = (
            audit_log["pipeline_run"]["severity_breakdown"].get(sev, 0) + 1
        )

    audit_path = output_dir / "audit_log.json"
    with open(audit_path, "w") as f:
        json.dump(audit_log, f, indent=2)
    print(f"  ✓ Audit log saved → {audit_path}")


def print_summary(flags, incidents):
    """Print a summary table to console."""
    print(f"\n{'='*70}")
    print(f"  PIPELINE SUMMARY")
    print(f"{'='*70}")
    print(f"  Flags raised:     {len(flags)}")
    print(f"  Incidents triaged: {len(incidents)}")
    print()

    # Severity breakdown
    sev_counts = {}
    for inc in incidents:
        sev = inc.get("severity", "unknown")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    print(f"  Severity Breakdown:")
    severity_colors = {"escalate": "🔴", "watch": "🟡", "dismiss": "🟢"}
    for sev in ["escalate", "watch", "dismiss"]:
        count = sev_counts.get(sev, 0)
        icon = severity_colors.get(sev, "⚪")
        print(f"    {icon} {sev.upper():>10}: {count}")

    print(f"\n  {'─'*66}")
    print(f"  {'ID':<10} {'SEVERITY':<12} {'CONF':>6}  {'TITLE':<40}")
    print(f"  {'─'*66}")

    for inc in incidents:
        inc_id = inc.get("incident_id", "?")
        severity = inc.get("severity", "?").upper()
        confidence = inc.get("confidence", 0)
        title = inc.get("title", "N/A")[:40]
        icon = severity_colors.get(inc.get("severity", ""), "⚪")
        print(f"  {icon} {inc_id:<8} {severity:<12} {confidence:>5.2f}  {title}")

    print(f"  {'─'*66}")

    # Print explanations
    print(f"\n  INCIDENT DETAILS:")
    for inc in incidents:
        sev = inc.get("severity", "?")
        icon = severity_colors.get(sev, "⚪")
        print(f"\n  {icon} {inc.get('incident_id', '?')} — {inc.get('title', 'N/A')}")
        print(f"     Severity: {sev.upper()} | Confidence: {inc.get('confidence', '?')}")
        print(f"     Explanation: {inc.get('explanation', 'N/A')}")
        print(f"     Action: {inc.get('recommended_action', 'N/A')}")
        if inc.get("audit", {}).get("reasoning_steps"):
            print(f"     Reasoning:")
            for step in inc["audit"]["reasoning_steps"][:5]:
                print(f"       • {step}")


def main():
    """Run the full pipeline."""
    # Load .env for API keys
    try:
        from dotenv import load_dotenv
        load_dotenv(PROJECT_ROOT / ".env")
    except ImportError:
        pass  # dotenv not installed, rely on environment variables

    print()
    print(f"{'═'*70}")
    print(f"  🛡️  AI SOC INSIGHT PIPELINE — Razorpay Security")
    print(f"{'═'*70}")
    
    start_time = time.time()

    # Stage 0: Load data
    print(f"\n📦 STAGE 0 — Loading events...")
    events = load_events()

    # Stage 1: Detector
    print(f"\n🔍 STAGE 1 — Running anomaly detector...")
    flags = run_detector(events)
    print(f"  ✓ Detector complete: {len(flags)} flags raised")
    
    for flag in flags:
        print(f"    [{flag['severity_hint'].upper():>8}] {flag['flag_id']} — {flag['rule']} "
              f"({len(flag['events'])} events)")

    # Stage 2: Copilot
    print(f"\n🧠 STAGE 2 — Running LLM triage copilot...")
    incidents = run_copilot(flags, events)
    print(f"  ✓ Triage complete: {len(incidents)} incidents assessed")

    # Save outputs
    print(f"\n💾 Saving outputs...")
    save_outputs(flags, incidents, events)

    # Summary
    elapsed = time.time() - start_time
    print_summary(flags, incidents)
    
    print(f"\n  ⏱ Pipeline completed in {elapsed:.1f}s")
    print(f"{'═'*70}\n")

    return incidents


if __name__ == "__main__":
    main()
